import { initialize, INode, NodeBuilder, unmarshal } from "./wacore.ts";

await initialize();

const messageNode = {
  tag: "message",
  attrs: {
    to: "1234567890@s.whatsapp.net",
    id: "ABC-123",
    type: "text",
  },
  content: [
    {
      tag: "body",
      content: [{ tag: "text", attrs: { value: "Hello from WASM!" } }],
    },
  ],
} satisfies INode;

const binaryData = new NodeBuilder(messageNode.tag)
  .attr("to", messageNode.attrs.to)
  .attr("id", messageNode.attrs.id)
  .attr("type", messageNode.attrs.type)
  .children(messageNode.content)
  .build();

const unmarshalledNode = unmarshal(binaryData);

console.log(unmarshalledNode);
