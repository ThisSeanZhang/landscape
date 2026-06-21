use std::{
    collections::HashSet,
    io::{self, Write},
};

use landscape_common::{
    config::StoreRuntimeConfig,
    error::{LdError, LdResult},
    VERSION,
};
use migration::{sea_orm::ConnectOptions, Migrator, MigratorTrait};
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

// Keep only the latest product release for each schema boundary.
pub const RELEASE_BOUNDARIES: &[ReleaseBoundary] = &[
    ReleaseBoundary {
        version: "0.16.3",
        terminal_migration: "m20260302_060012_cert_management",
    },
    ReleaseBoundary {
        version: "0.17.6",
        terminal_migration: "m20260314_120000_dns_redirect_answer_mode",
    },
    ReleaseBoundary {
        version: "0.18.3",
        terminal_migration: "m20260408_120000_lan_ipv6_v2",
    },
    ReleaseBoundary {
        version: "0.19.0",
        terminal_migration: "m20260502_080437_enrolled_device_dhcp_options",
    },
    ReleaseBoundary {
        version: "0.20.1",
        terminal_migration: "m20260504_000000_flow_device_match",
    },
    ReleaseBoundary {
        version: "0.21.0",
        terminal_migration: "m20260620_000000_split_static_nat_v4_v6",
    },
];

pub async fn interactive_rollback(config: &StoreRuntimeConfig) -> LdResult<()> {
    let opt: ConnectOptions = config.database_path.clone().into();
    let database = Database::connect(opt).await?;
    interactive_rollback_with_database(&database).await
}

async fn interactive_rollback_with_database(database: &DatabaseConnection) -> LdResult<()> {
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
) -> LdResult<()> {
    if boundaries.is_empty() {
        return Err(LdError::DbMsg("No release boundaries are configured.".to_string()));
    }

    let mut seen_versions = HashSet::new();
    let mut seen_migrations = HashSet::new();
    let mut previous_index = None;

    for boundary in boundaries {
        if !seen_versions.insert(boundary.version) {
            return Err(LdError::DbMsg(format!(
                "Duplicate release version '{}' in rollback boundaries.",
                boundary.version
            )));
        }

        if !seen_migrations.insert(boundary.terminal_migration) {
            return Err(LdError::DbMsg(format!(
                "Duplicate terminal migration '{}' in rollback boundaries.",
                boundary.terminal_migration
            )));
        }

        let index = migration_index(all_migrations, boundary.terminal_migration)?;
        if let Some(previous_index) = previous_index {
            if index <= previous_index {
                return Err(LdError::DbMsg(format!(
                    "Rollback boundaries are not ordered by migration sequence: '{}' is out of order.",
                    boundary.version
                )));
            }
        }
        previous_index = Some(index);
    }

    Ok(())
}

fn build_rollback_targets(
    current_state: &CurrentSchemaState,
    all_migrations: &[String],
    boundaries: &[ReleaseBoundary],
) -> LdResult<Vec<RollbackTarget>> {
    let mut raw_targets = Vec::new();

    for boundary in boundaries.iter().rev() {
        let target_index = migration_index(all_migrations, boundary.terminal_migration)?;
        if target_index < current_state.head_index {
            raw_targets.push((*boundary, (current_state.head_index - target_index) as u32));
        }
    }

    let mut targets = Vec::with_capacity(raw_targets.len());
    let mut previous_release_assigned = false;
    for (boundary, steps) in raw_targets {
        let is_current_release_boundary = current_state
            .release_boundary
            .is_some_and(|release| release.version == boundary.version)
            && !current_state.pending_since_release.is_empty();

        let display_label = if is_current_release_boundary {
            format!("current release boundary {}", boundary.version)
        } else if !previous_release_assigned {
            previous_release_assigned = true;
            format!("previous release {}", boundary.version)
        } else {
            format!("older release {}", boundary.version)
        };

        targets.push(RollbackTarget {
            version: boundary.version,
            display_label,
            terminal_migration: boundary.terminal_migration,
            steps,
        });
    }

    Ok(targets)
}

fn build_rollback_plan(
    current_state: &CurrentSchemaState,
    target: &RollbackTarget,
    all_migrations: &[String],
) -> LdResult<RollbackPlan> {
    let target_index = migration_index(all_migrations, target.terminal_migration)?;
    if target_index >= current_state.head_index {
        return Err(LdError::DbMsg(format!(
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
) -> LdResult<()> {
    Migrator::down(database, Some(plan.steps)).await?;
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
) -> LdResult<CurrentSchemaState> {
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
) -> LdResult<Option<ReleaseBoundary>> {
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

fn migration_index(all_migrations: &[String], migration_name: &str) -> LdResult<usize> {
    all_migrations
        .iter()
        .position(|name| name == migration_name)
        .ok_or_else(|| {
            LdError::DbMsg(format!(
                "Migration '{}' is not present in this build. Use the legacy step-based rollback path for manual recovery.",
                migration_name
            ))
        })
}

fn print_targets(current_state: &CurrentSchemaState, targets: &[RollbackTarget]) {
    println!("Current release: {}", current_state.release_label);
    println!("Current DB head: {}", current_state.head);
    if let Some(boundary) = current_state.release_boundary {
        if !current_state.pending_since_release.is_empty() {
            let step_label = if current_state.pending_since_release.len() == 1 {
                "migration"
            } else {
                "migrations"
            };
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
    }
    println!();
    println!("Available rollback targets:");
    println!(
        "Each target keeps the listed migration applied and rolls back newer migrations only."
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

fn prompt_target_selection<'a>(targets: &'a [RollbackTarget]) -> LdResult<&'a RollbackTarget> {
    let input = prompt("Select a target by number: ")?;
    let selection: usize = input
        .parse()
        .map_err(|_| LdError::DbMsg(format!("Invalid rollback selection '{}'.", input)))?;
    if selection == 0 {
        return Err(LdError::DbMsg("Rollback target selection must start at 1.".to_string()));
    }

    targets
        .get(selection - 1)
        .ok_or_else(|| LdError::DbMsg(format!("Rollback target '{}' is out of range.", selection)))
}

fn confirm_target_version(target_version: &str) -> LdResult<bool> {
    let confirmation = prompt(&format!("Type '{}' to confirm rollback: ", target_version))?;
    Ok(confirmation == target_version)
}

fn prompt(message: &str) -> LdResult<String> {
    print!("{message}");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

#[cfg(test)]
mod tests {
    use migration::MigratorTrait;
    use sea_orm::Database;

    use super::*;

    #[test]
    fn release_boundaries_match_current_migrations() {
        let all_migrations = migration_names();
        validate_release_boundaries(&all_migrations, RELEASE_BOUNDARIES).unwrap();
    }

    #[test]
    fn rollback_targets_are_computed_from_current_head() {
        let all_migrations = migration_names();
        let current_head = all_migrations.last().unwrap().clone();
        let current_state =
            resolve_current_state(&current_head, &all_migrations, RELEASE_BOUNDARIES).unwrap();
        let targets =
            build_rollback_targets(&current_state, &all_migrations, RELEASE_BOUNDARIES).unwrap();

        assert_eq!(targets.first().unwrap().version, "0.20.1");
        assert_eq!(targets.first().unwrap().display_label, "previous release 0.20.1");
        assert_eq!(targets.get(1).unwrap().display_label, "older release 0.19.0");
        assert_eq!(targets.first().unwrap().steps, 1);
    }

    #[test]
    fn rollback_plan_lists_migrations_in_reverse_order() {
        let all_migrations = migration_names();
        let current_head = all_migrations.last().unwrap().clone();
        let current_state =
            resolve_current_state(&current_head, &all_migrations, RELEASE_BOUNDARIES).unwrap();
        let target = build_rollback_targets(&current_state, &all_migrations, RELEASE_BOUNDARIES)
            .unwrap()
            .into_iter()
            .find(|target| target.version == "0.19.0")
            .unwrap();

        let plan = build_rollback_plan(&current_state, &target, &all_migrations).unwrap();
        assert_eq!(plan.steps, 3);
        assert_eq!(
            plan.rollback_migrations,
            vec![
                "m20260620_000000_split_static_nat_v4_v6".to_string(),
                "m20260504_000000_flow_device_match".to_string(),
                "m20260503_213507_static_nat_lan_target".to_string(),
            ]
        );
        assert!(!plan.rollback_migrations.contains(&target.terminal_migration.to_string()));
    }

    #[test]
    fn rollback_targets_exclude_current_boundary() {
        let all_migrations = migration_names();
        let current_head = "m20260408_120000_lan_ipv6_v2";
        let current_state =
            resolve_current_state(current_head, &all_migrations, RELEASE_BOUNDARIES).unwrap();
        let targets =
            build_rollback_targets(&current_state, &all_migrations, RELEASE_BOUNDARIES).unwrap();

        assert_eq!(current_state.release_label, "0.18.3");
        assert!(targets.iter().all(|target| target.version != "0.18.3"));
        assert_eq!(targets.first().unwrap().version, "0.17.6");
    }

    #[test]
    fn rollback_to_boundary_keeps_target_migration_applied() {
        let all_migrations = migration_names();
        let current_head = "m20260419_085215_flow_target_weights";
        let current_state =
            resolve_current_state(current_head, &all_migrations, RELEASE_BOUNDARIES).unwrap();
        let target = build_rollback_targets(&current_state, &all_migrations, RELEASE_BOUNDARIES)
            .unwrap()
            .into_iter()
            .find(|target| target.version == "0.18.3")
            .unwrap();

        let plan = build_rollback_plan(&current_state, &target, &all_migrations).unwrap();
        assert_eq!(plan.target_head, "m20260408_120000_lan_ipv6_v2");
        assert_eq!(plan.steps, 1);
        assert_eq!(
            plan.rollback_migrations,
            vec!["m20260419_085215_flow_target_weights".to_string()]
        );
    }

    #[tokio::test]
    async fn execute_rollback_plan_moves_database_to_target_boundary() {
        let database = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&database, None).await.unwrap();

        let all_migrations = migration_names();
        let current_head = applied_migration_names(&database).await.unwrap().pop().unwrap();
        let current_state =
            resolve_current_state(&current_head, &all_migrations, RELEASE_BOUNDARIES).unwrap();
        let target = build_rollback_targets(&current_state, &all_migrations, RELEASE_BOUNDARIES)
            .unwrap()
            .into_iter()
            .find(|target| target.version == "0.18.3")
            .unwrap();
        let plan = build_rollback_plan(&current_state, &target, &all_migrations).unwrap();

        execute_rollback_plan(&database, &plan).await.unwrap();

        let applied = applied_migration_names(&database).await.unwrap();
        assert_eq!(applied.last().unwrap(), plan.target_head);
    }
}
