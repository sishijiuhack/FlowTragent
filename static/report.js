import mermaid from "https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs";

mermaid.initialize({
  startOnLoad: true,
  securityLevel: "loose",
  theme: "base",
  themeVariables: {
    primaryColor: "#f7f8fa",
    primaryTextColor: "#171a1f",
    primaryBorderColor: "#cfd4da",
    lineColor: "#69707a",
    secondaryColor: "#ffffff",
    tertiaryColor: "#eef0f3",
    fontFamily: "Arial, Microsoft YaHei, sans-serif"
  },
  flowchart: { htmlLabels: true, curve: "basis" }
});
