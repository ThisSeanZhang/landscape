use std::{
    collections::HashSet,
    io::{self, Write},
};

use landscape_common::{VERSION, config::StoreRuntimeConfig, database::error::DbError};
use migration::{Migrator, MigratorTrait, sea_orm::ConnectOptions};
use sea_orm::{Database, DatabaseConnection};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReleaseBoundary {
    pub version: &'static str,
    pub terminal_migration: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RollbackTarget {
    pub version: &'static str,
    pub display_label: String,
    pub terminal_migration: &'static str,
    pub steps: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RollbackPlan {
    pub current_release_label: String,
    pub current_head: String,
    pub target_label: String,
    pub target_version: &'static str,
    pub target_head: &'static str,
    pub steps: u32,
    pub rollback_migrations: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CurrentSchemaState {
    release_label: String,
    release_boundary: Option<ReleaseBoundary>,
    head: String,
    head_index: usize,
    pending_since_release: Vec<String>,
}

// Rollback only guarantees the previous release: keep exactly the two newest
// boundaries here (current release + previous release). At each release,
// append the new boundary and drop the oldest. Older schema states are
// reached via the manual step-based rollback path.
pub const RELEASE_BOUNDARIES: &[ReleaseBoundary] = &[
    ReleaseBoundary {
        version: "0.25.1",
        terminal_migration: "m20260927_000000_add_use_experimental_pool_to_dns_upstream",
    },
    ReleaseBoundary {
        version: "0.26.0",
        terminal_migration: "m20261008_240001_wan_link_health_check",
    },
];

pub async fn interactive_rollback(config: &StoreRuntimeConfig) -> Result<(), DbError> {
    let opt: ConnectOptions = config.database_path.clone().into();
    let database = Database::connect(opt).await?;
    interactive_rollback_with_database(&database).await
}

async fn interactive_rollback_with_database(database: &DatabaseConnection) -> Result<(), DbError> {
    let all_migrations = migration_names();
    validate_release_boundaries(&all_migrations, RELEASE_BOUNDARIES)?;

    let applied = applied_migration_names(database).await?;
    let Some(current_head) = applied.last().cloned() else {
        println!("Database has no applied migrations, nothing to roll back.");
        return Ok(());
    };

    let current_state = resolve_current_state(&current_head, &all_migrations, RELEASE_BOUNDARIES)?;
    let targets = build_rollback_targets(&current_state, &all_migrations, RELEASE_BOUNDARIES)?;
    if targets.is_empty() {
        println!("No registered rollback targets older than the current schema head.");
        return Ok(());
    }

    print_targets(&current_state, &targets);
    let target = prompt_target_selection(&targets)?;
    let plan = build_rollback_plan(&current_state, target, &all_migrations)?;
    print_plan_preview(&plan);

    if !confirm_target_version(plan.target_version)? {
        println!("Rollback cancelled.");
        return Ok(());
    }

    execute_rollback_plan(database, &plan).await?;
    println!(
        "Rollback complete. Current schema target is now {} ({})",
        plan.target_version, plan.target_head
    );
    Ok(())
}

pub fn validate_release_boundaries(
    all_migrations: &[String],
    boundaries: &[ReleaseBoundary],
) -> Result<(), DbError> {
    if boundaries.is_empty() {
        return Err(DbError::Internal("No release boundaries are configured.".to_string()));
    }

    let mut seen_versions = HashSet::new();
    let mut seen_migrations = HashSet::new();
    let mut previous_index = None;

    for boundary in boundaries {
        if !seen_versions.insert(boundary.version) {
            return Err(DbError::Internal(format!(
                "Duplicate release version '{}' in rollback boundaries.",
                boundary.version
            )));
        }

        if !seen_migrations.insert(boundary.terminal_migration) {
            return Err(DbError::Internal(format!(
                "Duplicate terminal migration '{}' in rollback boundaries.",
                boundary.terminal_migration
            )));
        }

        let index = migration_index(all_migrations, boundary.terminal_migration)?;
        if let Some(previous_index) = previous_index
            && index <= previous_index
        {
            return Err(DbError::Internal(format!(
                "Rollback boundaries are not ordered by migration sequence: '{}' is out of order.",
                boundary.version
            )));
        }
        previous_index = Some(index);
    }

    Ok(())
}

fn build_rollback_targets(
    current_state: &CurrentSchemaState,
    all_migrations: &[String],
    boundaries: &[ReleaseBoundary],
) -> Result<Vec<RollbackTarget>, DbError> {
    let mut targets = Vec::new();

    for boundary in boundaries.iter().rev() {
        let target_index = migration_index(all_migrations, boundary.terminal_migration)?;
        if target_index >= current_state.head_index {
            continue;
        }

        let is_current_release_boundary = current_state
            .release_boundary
            .is_some_and(|release| release.version == boundary.version)
            && !current_state.pending_since_release.is_empty();

        let display_label = if is_current_release_boundary {
            format!("current release boundary {}", boundary.version)
        } else {
            format!("previous release {}", boundary.version)
        };

        targets.push(RollbackTarget {
            version: boundary.version,
            display_label,
            terminal_migration: boundary.terminal_migration,
            steps: (current_state.head_index - target_index) as u32,
        });

        // Only the current release boundary (undoing unreleased migrations)
        // and the previous release are offered, even if more boundaries exist.
        if !is_current_release_boundary {
            break;
        }
    }

    Ok(targets)
}

fn build_rollback_plan(
    current_state: &CurrentSchemaState,
    target: &RollbackTarget,
    all_migrations: &[String],
) -> Result<RollbackPlan, DbError> {
    let target_index = migration_index(all_migrations, target.terminal_migration)?;
    if target_index >= current_state.head_index {
        return Err(DbError::Internal(format!(
            "Target version '{}' is not older than the current schema head.",
            target.version
        )));
    }

    let rollback_migrations = all_migrations[(target_index + 1)..=current_state.head_index]
        .iter()
        .rev()
        .cloned()
        .collect();

    Ok(RollbackPlan {
        current_release_label: current_state.release_label.clone(),
        current_head: current_state.head.clone(),
        target_label: target.display_label.clone(),
        target_version: target.version,
        target_head: target.terminal_migration,
        steps: target.steps,
        rollback_migrations,
    })
}

pub async fn execute_rollback_plan(
    database: &DatabaseConnection,
    plan: &RollbackPlan,
) -> Result<(), DbError> {
    // Each rolled-back migration runs in its own transaction (schema change
    // and seaql_migrations row removed atomically), so an interrupted
    // rollback can be retried instead of leaving a half-rolled-back schema.
    migration::runner::down_transactional::<Migrator, _>(database, Some(plan.steps)).await?;
    Ok(())
}

async fn applied_migration_names(
    database: &DatabaseConnection,
) -> Result<Vec<String>, sea_orm::DbErr> {
    Ok(Migrator::get_migration_models(database)
        .await?
        .into_iter()
        .map(|model| model.version)
        .collect())
}

fn resolve_current_state(
    current_head: &str,
    all_migrations: &[String],
    boundaries: &[ReleaseBoundary],
) -> Result<CurrentSchemaState, DbError> {
    let head_index = migration_index(all_migrations, current_head)?;
    let release_boundary = current_release_boundary(head_index, all_migrations, boundaries)?;
    let pending_since_release = if let Some(boundary) = release_boundary {
        let release_index = migration_index(all_migrations, boundary.terminal_migration)?;
        if head_index > release_index {
            all_migrations[(release_index + 1)..=head_index].to_vec()
        } else {
            vec![]
        }
    } else {
        vec![]
    };

    let release_label = match release_boundary {
        Some(boundary) if pending_since_release.is_empty() => boundary.version.to_string(),
        Some(boundary) => format!(
            "{} (+{} unreleased migration{})",
            boundary.version,
            pending_since_release.len(),
            if pending_since_release.len() == 1 { "" } else { "s" }
        ),
        None => format!("{VERSION} (custom schema)"),
    };

    Ok(CurrentSchemaState {
        release_label,
        release_boundary,
        head: current_head.to_string(),
        head_index,
        pending_since_release,
    })
}

fn current_release_boundary(
    head_index: usize,
    all_migrations: &[String],
    boundaries: &[ReleaseBoundary],
) -> Result<Option<ReleaseBoundary>, DbError> {
    if let Some(boundary) = boundaries.iter().find(|boundary| boundary.version == VERSION) {
        let version_index = migration_index(all_migrations, boundary.terminal_migration)?;
        if version_index <= head_index {
            return Ok(Some(*boundary));
        }
    }

    for boundary in boundaries.iter().rev() {
        let boundary_index = migration_index(all_migrations, boundary.terminal_migration)?;
        if boundary_index <= head_index {
            return Ok(Some(*boundary));
        }
    }

    Ok(None)
}

fn migration_names() -> Vec<String> {
    Migrator::get_migration_files()
        .into_iter()
        .map(|migration| migration.name().to_string())
        .collect()
}

fn migration_index(all_migrations: &[String], migration_name: &str) -> Result<usize, DbError> {
    all_migrations
        .iter()
        .position(|name| name == migration_name)
        .ok_or_else(|| {
            DbError::Internal(format!(
                "Migration '{}' is not present in this build. Use the legacy step-based rollback path for manual recovery.",
                migration_name
            ))
        })
}

fn print_targets(current_state: &CurrentSchemaState, targets: &[RollbackTarget]) {
    println!("Current release: {}", current_state.release_label);
    println!("Current DB head: {}", current_state.head);
    if let Some(boundary) = current_state.release_boundary
        && !current_state.pending_since_release.is_empty()
    {
        let step_label =
            if current_state.pending_since_release.len() == 1 { "migration" } else { "migrations" };
        println!(
            "Current DB is ahead of the {} release boundary ({}) by {} {}:",
            boundary.version,
            boundary.terminal_migration,
            current_state.pending_since_release.len(),
            step_label
        );
        for migration in &current_state.pending_since_release {
            println!("  - {}", migration);
        }
    }
    println!();
    println!("Available rollback targets:");
    println!(
        "Each target keeps the listed migration applied and rolls back newer migrations only."
    );
    println!(
        "Only the previous release is guaranteed; deeper rollbacks use the manual step-based path."
    );

    for (index, target) in targets.iter().enumerate() {
        let step_label = if target.steps == 1 { "step" } else { "steps" };
        let migration_label = if target.steps == 1 { "migration" } else { "migrations" };
        println!(
            "[{}] {} (keep {}, rollback {} newer {} / {} {})",
            index + 1,
            target.display_label,
            target.terminal_migration,
            target.steps,
            migration_label,
            target.steps,
            step_label
        );
    }
}

fn print_plan_preview(plan: &RollbackPlan) {
    println!();
    println!("Rollback preview:");
    println!("  Current release: {}", plan.current_release_label);
    println!("  Current head:    {}", plan.current_head);
    println!("  Target:          {}", plan.target_label);
    println!("  Target version:  {}", plan.target_version);
    println!("  Target head:     {} (will remain applied)", plan.target_head);
    println!("  Steps:           {}", plan.steps);
    println!("  Migrations to rollback (newer than target head):");
    for migration in &plan.rollback_migrations {
        println!("    - {}", migration);
    }
    println!();
}

fn prompt_target_selection(targets: &[RollbackTarget]) -> Result<&RollbackTarget, DbError> {
    let input = prompt("Select a target by number: ")?;
    let selection: usize = input
        .parse()
        .map_err(|_| DbError::Internal(format!("Invalid rollback selection '{}'.", input)))?;
    if selection == 0 {
        return Err(DbError::Internal("Rollback target selection must start at 1.".to_string()));
    }

    targets.get(selection - 1).ok_or_else(|| {
        DbError::Internal(format!("Rollback target '{}' is out of range.", selection))
    })
}

fn confirm_target_version(target_version: &str) -> Result<bool, DbError> {
    let confirmation = prompt(&format!("Type '{}' to confirm rollback: ", target_version))?;
    Ok(confirmation == target_version)
}

fn prompt(message: &str) -> Result<String, DbError> {
    print!("{message}");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

#[cfg(test)]
mod tests {
    use sea_orm::Database;

    use super::*;

    #[test]
    fn release_boundaries_match_current_migrations() {
        let all_migrations = migration_names();
        validate_release_boundaries(&all_migrations, RELEASE_BOUNDARIES).unwrap();

        // Rollback window: exactly the current and the previous release.
        assert_eq!(
            RELEASE_BOUNDARIES.len(),
            2,
            "keep only the two newest boundaries; drop the oldest at each release"
        );

        // Release checklist: the newest migration must terminate a boundary,
        // otherwise the release that ships it has no rollback target.
        assert_eq!(
            RELEASE_BOUNDARIES.last().unwrap().terminal_migration,
            all_migrations.last().unwrap(),
            "newest migration has no release boundary; register it before releasing"
        );
    }

    fn synthetic_migrations() -> Vec<String> {
        (1..=8).map(|i| format!("m{i:03}")).collect()
    }

    fn synthetic_boundaries() -> [ReleaseBoundary; 3] {
        [
            ReleaseBoundary { version: "1.0.0", terminal_migration: "m002" },
            ReleaseBoundary { version: "1.1.0", terminal_migration: "m004" },
            ReleaseBoundary { version: "1.2.0", terminal_migration: "m006" },
        ]
    }

    #[test]
    fn rollback_targets_stop_at_previous_release() {
        let all_migrations = synthetic_migrations();
        let boundaries = &synthetic_boundaries();

        // Head beyond the newest boundary: it is offered to undo unreleased
        // migrations, followed by the previous release — nothing deeper even
        // though a third boundary exists.
        let state = resolve_current_state("m008", &all_migrations, boundaries).unwrap();
        assert_eq!(state.release_label, "1.2.0 (+2 unreleased migrations)");
        let targets = build_rollback_targets(&state, &all_migrations, boundaries).unwrap();
        let labels: Vec<_> = targets.iter().map(|target| target.display_label.as_str()).collect();
        assert_eq!(labels, vec!["current release boundary 1.2.0", "previous release 1.1.0"]);
        let steps: Vec<_> = targets.iter().map(|target| target.steps).collect();
        assert_eq!(steps, vec![2, 4]);
        assert!(targets.iter().all(|target| target.version != "1.0.0"));

        // Head exactly on the newest boundary: only the previous release is
        // offered, never the boundary the head sits on.
        let state = resolve_current_state("m006", &all_migrations, boundaries).unwrap();
        assert_eq!(state.release_label, "1.2.0");
        let targets = build_rollback_targets(&state, &all_migrations, boundaries).unwrap();
        let labels: Vec<_> = targets.iter().map(|target| target.display_label.as_str()).collect();
        assert_eq!(labels, vec!["previous release 1.1.0"]);
        assert!(targets.iter().all(|target| target.version != "1.2.0"));
    }

    #[test]
    fn rollback_plan_rolls_back_newer_migrations_in_reverse_order() {
        let all_migrations = synthetic_migrations();
        let boundaries = &synthetic_boundaries();
        let state = resolve_current_state("m008", &all_migrations, boundaries).unwrap();
        let target = build_rollback_targets(&state, &all_migrations, boundaries)
            .unwrap()
            .into_iter()
            .find(|target| target.version == "1.1.0")
            .unwrap();

        let plan = build_rollback_plan(&state, &target, &all_migrations).unwrap();
        assert_eq!(plan.steps, 4);
        assert_eq!(plan.target_head, "m004");
        assert_eq!(
            plan.rollback_migrations,
            vec!["m008".to_string(), "m007".to_string(), "m006".to_string(), "m005".to_string(),]
        );
        assert!(!plan.rollback_migrations.contains(&target.terminal_migration.to_string()));
    }

    #[test]
    fn rollback_plan_rejects_target_not_older_than_head() {
        let all_migrations = synthetic_migrations();
        let boundaries = &synthetic_boundaries();
        let state = resolve_current_state("m006", &all_migrations, boundaries).unwrap();

        let at_head = RollbackTarget {
            version: "1.2.0",
            display_label: "current release boundary 1.2.0".to_string(),
            terminal_migration: "m006",
            steps: 0,
        };
        assert!(build_rollback_plan(&state, &at_head, &all_migrations).is_err());
    }

    #[tokio::test]
    async fn execute_rollback_plan_moves_database_to_target_boundary() {
        // in-memory DB: every connection is a separate database, so force a single connection
        let mut opt: ConnectOptions = "sqlite::memory:".into();
        opt.max_connections(1);
        let database = Database::connect(opt).await.unwrap();
        migration::runner::up_transactional::<Migrator, _>(&database, None).await.unwrap();

        let all_migrations = migration_names();
        let current_head = applied_migration_names(&database).await.unwrap().pop().unwrap();
        let current_state =
            resolve_current_state(&current_head, &all_migrations, RELEASE_BOUNDARIES).unwrap();
        let target = build_rollback_targets(&current_state, &all_migrations, RELEASE_BOUNDARIES)
            .unwrap()
            .into_iter()
            .find(|target| target.version == "0.25.1")
            .unwrap();
        let plan = build_rollback_plan(&current_state, &target, &all_migrations).unwrap();

        execute_rollback_plan(&database, &plan).await.unwrap();

        let applied = applied_migration_names(&database).await.unwrap();
        assert_eq!(applied.last().unwrap(), plan.target_head);
    }
}
