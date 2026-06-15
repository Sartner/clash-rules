function main(config) {
  const STATIC_PROXY_NAME = "🏠 静态住宅节点";
  const CLAUDE_GROUP_NAME = "🌩️ Claude AI";

  // 这里填写你的静态住宅节点参数
  const staticProxyOverride = {
    name: STATIC_PROXY_NAME,
    type: "socks5",          // 按你的实际类型改：http / socks5 / trojan / ss 等
    server: "1.1.1.1",
    port: 20034,
    username: "change-me",
    password: "change-me",
    udp: true
  };

  config.proxies = config.proxies || [];
  config["proxy-groups"] = config["proxy-groups"] || [];

  const proxy = config.proxies.find(p => p.name === STATIC_PROXY_NAME);
  const claudeGroup = config["proxy-groups"].find(g => g.name === CLAUDE_GROUP_NAME);

  if (proxy) {
    // 1. 找到静态住宅节点，覆盖节点属性
    Object.assign(proxy, staticProxyOverride);

    // 2. 覆盖成功后，把 Claude AI 策略组设置为该节点
    if (claudeGroup) {
      claudeGroup.type = "select";
      claudeGroup.proxies = [STATIC_PROXY_NAME];

      // 避免原来通过 proxy-providers/use 引入其他节点
      delete claudeGroup.use;
    } else {
      config["proxy-groups"].push({
        name: CLAUDE_GROUP_NAME,
        type: "select",
        proxies: [STATIC_PROXY_NAME]
      });
    }
  } else {
    // 没找到静态住宅节点，则 Claude AI 走 REJECT
    if (claudeGroup) {
      claudeGroup.type = "select";
      claudeGroup.proxies = ["REJECT"];

      delete claudeGroup.use;
    } else {
      config["proxy-groups"].push({
        name: CLAUDE_GROUP_NAME,
        type: "select",
        proxies: ["REJECT"]
      });
    }
  }

  return config;
}
