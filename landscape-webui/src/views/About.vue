<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import { Book, LogoGithub, Renew, UserAvatar } from "@vicons/carbon";

interface GitHubContributor {
  id?: number;
  login?: string;
  name?: string;
  email?: string;
  avatar_url?: string;
  html_url?: string;
  contributions: number;
}

interface GitHubRepository {
  full_name: string;
  contributors_url: string;
}

const REPOSITORY_URL = "https://github.com/ThisSeanZhang/landscape";
const ORGANIZATION_URL = "https://github.com/landscape-router";
const ORGANIZATION_REPOSITORIES_URL =
  "https://api.github.com/orgs/landscape-router/repos";
const REPOSITORY_CONTRIBUTORS_URL =
  "https://api.github.com/repos/ThisSeanZhang/landscape/contributors";
const LICENSE_URL = `${REPOSITORY_URL}/blob/main/LICENSE`;
const DOC_URL = "https://landscape.whileaway.dev/";
const GITHUB_HEADERS = {
  Accept: "application/vnd.github+json",
  "X-GitHub-Api-Version": "2022-11-28",
};

const { t } = useI18n();
const contributors = ref<GitHubContributor[]>([]);
const loading = ref(false);
const failed = ref(false);
let requestController: AbortController | undefined;
const windowWidth = ref(window.innerWidth);

const skeletonCount = computed(() => {
  const width = windowWidth.value;
  if (width < 360) return 1;
  if (width < 680) return 2;
  const containerWidth = Math.min(width, 1180);
  const innerWidth = containerWidth - 56;
  return Math.floor((innerWidth + 12) / 162);
});

function onResize() {
  windowWidth.value = window.innerWidth;
}

const versionLabel = computed(() =>
  t("about.version", { version: __APP_VERSION__ }),
);

function contributorName(contributor: GitHubContributor) {
  return contributor.login || contributor.name || t("about.anonymous");
}

function contributorKey(contributor: GitHubContributor, index: number) {
  return contributor.id || contributor.login || contributor.name || index;
}

function contributorIdentity(contributor: GitHubContributor) {
  if (contributor.id !== undefined) return `id:${contributor.id}`;
  if (contributor.login)
    return `login:${contributor.login.toLocaleLowerCase()}`;
  if (contributor.email)
    return `email:${contributor.email.toLocaleLowerCase()}`;
  return `name:${contributor.name || t("about.anonymous")}`;
}

async function fetchAllPages<T>(
  endpoint: string,
  params: Record<string, string>,
  signal: AbortSignal,
) {
  const result: T[] = [];
  let page = 1;

  while (true) {
    const url = new URL(endpoint);
    Object.entries(params).forEach(([key, value]) =>
      url.searchParams.set(key, value),
    );
    url.searchParams.set("per_page", "100");
    url.searchParams.set("page", page.toString());

    const response = await fetch(url, {
      headers: GITHUB_HEADERS,
      signal,
    });

    if (!response.ok) throw new Error(`GitHub API returned ${response.status}`);

    const pageItems: unknown = await response.json();
    if (!Array.isArray(pageItems)) {
      throw new Error("GitHub API returned an invalid list");
    }

    result.push(...(pageItems as T[]));
    if (pageItems.length < 100) return result;
    page += 1;
  }
}

async function loadContributors() {
  requestController?.abort();
  const controller = new AbortController();
  requestController = controller;
  loading.value = true;
  failed.value = false;

  try {
    const repositories = await fetchAllPages<GitHubRepository>(
      ORGANIZATION_REPOSITORIES_URL,
      {
        type: "public",
        sort: "full_name",
        direction: "asc",
      },
      controller.signal,
    );

    const contributorEndpoints = [
      REPOSITORY_CONTRIBUTORS_URL,
      ...repositories.map((repository) => repository.contributors_url),
    ];
    const uniqueEndpoints = [...new Set(contributorEndpoints)];
    const contributorLists = await Promise.all(
      uniqueEndpoints.map((endpoint) =>
        fetchAllPages<GitHubContributor>(endpoint, {}, controller.signal),
      ),
    );

    const uniqueContributors = new Map<string, GitHubContributor>();
    contributorLists.flat().forEach((contributor) => {
      const identity = contributorIdentity(contributor);
      const existing = uniqueContributors.get(identity);

      if (existing) {
        uniqueContributors.set(identity, {
          ...existing,
          login: existing.login || contributor.login,
          name: existing.name || contributor.name,
          avatar_url: existing.avatar_url || contributor.avatar_url,
          html_url: existing.html_url || contributor.html_url,
          contributions:
            existing.contributions + (contributor.contributions || 0),
        });
      } else {
        uniqueContributors.set(identity, {
          ...contributor,
          contributions: contributor.contributions || 0,
        });
      }
    });

    const collator = new Intl.Collator(undefined, {
      numeric: true,
      sensitivity: "base",
    });
    contributors.value = [...uniqueContributors.values()].sort((a, b) => {
      const aIsThisSeanZhang = a.login?.toLocaleLowerCase() === "thisseanzhang";
      const bIsThisSeanZhang = b.login?.toLocaleLowerCase() === "thisseanzhang";

      if (aIsThisSeanZhang !== bIsThisSeanZhang) {
        return aIsThisSeanZhang ? 1 : -1;
      }

      const contributionDifference = b.contributions - a.contributions;
      if (contributionDifference !== 0) return contributionDifference;
      return collator.compare(contributorName(a), contributorName(b));
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") return;
    contributors.value = [];
    failed.value = true;
    console.error(error);
  } finally {
    if (requestController === controller) loading.value = false;
  }
}

onMounted(() => {
  loadContributors();
  window.addEventListener("resize", onResize);
});
onBeforeUnmount(() => {
  requestController?.abort();
  window.removeEventListener("resize", onResize);
});
</script>

<template>
  <main class="about-page">
    <section class="product-section">
      <div class="product-copy">
        <n-text depth="3" class="section-label">LANDSCAPE ROUTER</n-text>
        <h1>{{ t("about.title") }}</h1>
        <p>{{ t("about.description") }}</p>
        <n-tag size="small" :bordered="false">{{ versionLabel }}</n-tag>
      </div>

      <n-flex :size="8" class="product-actions">
        <n-button
          tag="a"
          :href="REPOSITORY_URL"
          target="_blank"
          rel="noopener noreferrer"
          secondary
        >
          <template #icon
            ><n-icon><LogoGithub /></n-icon
          ></template>
          {{ t("about.repository") }}
        </n-button>
        <n-button
          tag="a"
          :href="ORGANIZATION_URL"
          target="_blank"
          rel="noopener noreferrer"
          secondary
        >
          <template #icon
            ><n-icon><LogoGithub /></n-icon
          ></template>
          {{ t("about.organization") }}
        </n-button>
        <n-button
          tag="a"
          :href="LICENSE_URL"
          target="_blank"
          rel="noopener noreferrer"
          tertiary
        >
          {{ t("about.license") }}
        </n-button>
        <n-button
          tag="a"
          :href="DOC_URL"
          target="_blank"
          rel="noopener noreferrer"
          secondary
        >
          <template #icon
            ><n-icon><Book /></n-icon
          ></template>
          {{ t("about.documentation") }}
        </n-button>
      </n-flex>
    </section>

    <n-divider />

    <section class="contributors-section">
      <div class="section-header">
        <div>
          <n-flex align="center" :size="10">
            <h2>{{ t("about.contributors") }}</h2>
            <n-tag
              v-if="contributors.length"
              size="small"
              round
              :bordered="false"
            >
              {{ t("about.contributor_count", { count: contributors.length }) }}
            </n-tag>
          </n-flex>
          <p>{{ t("about.contributors_description") }}</p>
        </div>

        <n-tooltip trigger="hover">
          <template #trigger>
            <n-button
              quaternary
              circle
              :loading="loading"
              :aria-label="t('about.refresh')"
              @click="loadContributors"
            >
              <template #icon
                ><n-icon><Renew /></n-icon
              ></template>
            </n-button>
          </template>
          {{ t("about.refresh") }}
        </n-tooltip>
      </div>

      <div v-if="loading && !contributors.length" class="contributors-grid">
        <n-card v-for="index in skeletonCount" :key="index" size="small">
          <n-flex vertical align="center" :size="12">
            <n-skeleton circle height="72px" width="72px" />
            <n-skeleton text style="width: 72%" />
          </n-flex>
        </n-card>
      </div>

      <n-result
        v-else-if="failed"
        status="error"
        :title="t('about.load_failed')"
        :description="t('about.load_failed_description')"
      >
        <template #footer>
          <n-button secondary @click="loadContributors">
            <template #icon
              ><n-icon><Renew /></n-icon
            ></template>
            {{ t("about.retry") }}
          </n-button>
        </template>
      </n-result>

      <div v-else class="contributors-grid">
        <component
          :is="contributor.html_url ? 'a' : 'div'"
          v-for="(contributor, index) in contributors"
          :key="contributorKey(contributor, index)"
          class="contributor-link"
          :href="contributor.html_url"
          :target="contributor.html_url ? '_blank' : undefined"
          :rel="contributor.html_url ? 'noopener noreferrer' : undefined"
          :aria-label="
            contributor.html_url
              ? t('about.open_profile', { name: contributorName(contributor) })
              : undefined
          "
        >
          <n-card size="small" hoverable class="contributor-card">
            <n-flex vertical align="center" :size="10">
              <n-avatar
                v-if="contributor.avatar_url"
                round
                lazy
                :size="72"
                :src="contributor.avatar_url"
                object-fit="cover"
              >
                <template #fallback>
                  <n-icon size="32"><UserAvatar /></n-icon>
                </template>
              </n-avatar>
              <n-avatar v-else round :size="72">
                <n-icon size="32"><UserAvatar /></n-icon>
              </n-avatar>
              <n-ellipsis class="contributor-name">
                {{ contributorName(contributor) }}
              </n-ellipsis>
              <n-icon v-if="contributor.html_url" size="18" class="github-icon">
                <LogoGithub />
              </n-icon>
            </n-flex>
          </n-card>
        </component>
      </div>
    </section>
  </main>
</template>

<style scoped>
.about-page {
  box-sizing: border-box;
  width: 100%;
  max-width: 1180px;
  margin: 0 auto;
  padding: 36px 28px 48px;
}

.product-section {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: 32px;
}

.product-copy {
  min-width: 0;
}

.section-label {
  display: block;
  margin-bottom: 8px;
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0;
}

h1,
h2,
p {
  margin: 0;
}

h1 {
  margin-bottom: 8px;
  font-size: 30px;
  line-height: 1.2;
  letter-spacing: 0;
}

h2 {
  font-size: 20px;
  line-height: 1.3;
  letter-spacing: 0;
}

.product-copy p,
.section-header p {
  opacity: 0.72;
}

.product-copy p {
  margin-bottom: 14px;
  font-size: 15px;
}

.product-actions {
  flex-shrink: 0;
}

.contributors-section {
  padding-top: 4px;
}

.section-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 24px;
  margin-bottom: 22px;
}

.section-header p {
  margin-top: 6px;
  font-size: 14px;
}

.contributors-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
  gap: 12px;
}

.contributor-link {
  display: block;
  min-width: 0;
  color: inherit;
  text-decoration: none;
  transition: transform 0.2s ease;
}

a.contributor-link {
  cursor: pointer;
}

a.contributor-link:hover,
a.contributor-link:focus-visible {
  transform: translateY(-2px);
}

a.contributor-link:focus-visible {
  border-radius: 6px;
  outline: 2px solid currentColor;
  outline-offset: 2px;
}

.contributor-card {
  min-height: 152px;
}

:deep(.contributor-card > .n-card__content) {
  padding: 20px 14px 16px;
}

.contributor-name {
  width: 100%;
  text-align: center;
  font-size: 14px;
  font-weight: 600;
}

.github-icon {
  opacity: 0.58;
}

@media (max-width: 680px) {
  .about-page {
    padding: 24px 16px 36px;
  }

  .product-section {
    align-items: flex-start;
    flex-direction: column;
    gap: 20px;
  }

  .product-actions {
    width: 100%;
  }

  .contributors-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  h1 {
    font-size: 26px;
  }
}

@media (max-width: 360px) {
  .contributors-grid {
    grid-template-columns: 1fr;
  }
}
</style>
