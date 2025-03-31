import { NetDev } from "@/lib/dev";
import { FlowNodeType, LandscapeFlowNode } from ".";

// export function dev_to_node(devs: NetDev[]): LandscapeFlowNode[] {
//   let result: LandscapeFlowNode[] = [];
//   for (const dev_info of devs) {
//     result.push(
//       new LandscapeFlowNode({
//         id: `${dev_info.index}`,
//         label: dev_info.name,
//         position: { x: 0, y: 0 },
//         data: { t: FlowNodeType.Dev, dev: dev_info },
//       })
//     );
//   }
//   return result;
// }

// export function docker_to_node(devs: NetDev[]): LandscapeFlowNode[] {
//   let result: LandscapeFlowNode[] = [];
//   for (const dev_info of devs) {
//     result.push(
//       new LandscapeFlowNode({
//         id: `${dev_info.index}`,
//         label: dev_info.name,
//         position: { x: 0, y: 0 },
//         data: { t: FlowNodeType.Dev, dev: dev_info },
//       })
//     );
//   }
//   return result;
// }
