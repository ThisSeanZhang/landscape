import { GeoConfigKey } from "@/rust_bindings/common/geo";
import { NTag, NText, SelectOption } from "naive-ui";
import { h } from "vue";

/**
 * Sorts GeoConfigKey results by relevance to the query.
 * 1. Exact match (Key)
 * 2. Starts with (Key)
 * 3. Alphabetical (Key, then Name)
 */
export function sortGeoKeys(
  results: GeoConfigKey[],
  query: string
): GeoConfigKey[] {
  const q = (query || "").toUpperCase();
  if (!results) return [];

  return results.sort((a, b) => {
    const keyA = (a.key || "").toUpperCase();
    const keyB = (b.key || "").toUpperCase();
    const nameA = a.name || "";
    const nameB = b.name || "";

    // 1. Exact match
    if (keyA === q && keyB !== q) return -1;
    if (keyA !== q && keyB === q) return 1;

    // 2. Starts with
    const startA = keyA.startsWith(q);
    const startB = keyB.startsWith(q);
    if (startA && !startB) return -1;
    if (!startA && startB) return 1;

    // 3. Alphabetical
    return keyA.localeCompare(keyB) || nameA.localeCompare(nameB);
  });
}

/**
 * Renders the select option label with the Source Tag on the LEFT.
 * Handles overflow with ellipsis.
 */
export const renderGeoSelectLabel = (option: SelectOption) => {
  const data = option.data as GeoConfigKey | undefined;

  // Fallback if data is missing (e.g., when Select creates a fallback option for a value not in list)
  if (!data || !data.name) {
    return h("span", {}, { default: () => option.label });
  }

  return h(
    "div",
    {
      style: {
        display: "flex",
        alignItems: "center",
        width: "100%",
        overflow: "hidden", // Ensure container doesn't overflow
      },
    },
    [
      // Source Tag (Left)
      h(
        NTag,
        {
          size: "small",
          bordered: false,
          type: "default",
          style: {
            marginRight: "8px",
            fontSize: "12px",
            color: "#666",
            maxWidth: "80px", // Limit width of the tag
            flexShrink: 0, // Prevent tag from shrinking too much
          },
        },
        {
          default: () =>
            h(
              "div",
              {
                style: {
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  whiteSpace: "nowrap",
                },
                title: data.name, // Tooltip on hover
              },
              { default: () => data.name }
            ),
        }
      ),
      // Key (Right)
      h(
        "span",
        {
          style: {
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
            flex: 1, // Take remaining space
          },
          title: option.label as string, // Tooltip
        },
        { default: () => option.label }
      ),
    ]
  );
};
