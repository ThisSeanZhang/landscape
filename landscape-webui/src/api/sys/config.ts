import axiosService from "@/api";

export async function get_init_config(): Promise<void> {
  try {
    const response = await axiosService.get(`sys_service/config/export`, {
      responseType: "blob", // 重点！要加这一行，告诉 axios 你期望拿到 blob（二进制）
    });

    // 拿到 blob 数据
    const blob = response.data;

    // 解析 Content-Disposition 头，提取文件名（可选）
    const disposition = response.headers["content-disposition"];
    let filename = "landscape_init.toml"; // 默认文件名

    if (disposition && disposition.includes("filename=")) {
      const match = disposition.match(/filename="?([^"]+)"?/);
      if (match && match[1]) {
        filename = match[1];
      }
    }

    // 创建临时 URL
    const url = window.URL.createObjectURL(blob);

    // 创建 a 标签模拟点击
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();

    // 释放 URL
    window.URL.revokeObjectURL(url);
  } catch (error) {
    console.error("下载配置失败", error);
  }
}
