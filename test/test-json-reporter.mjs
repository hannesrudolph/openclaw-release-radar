function jsonReplacer(_key, value) {
  if (!(value instanceof Error)) return value;
  return {
    name: value.name,
    message: value.message,
    stack: value.stack,
    ...value,
  };
}

export default async function* jsonReporter(source) {
  for await (const event of source) {
    yield `${JSON.stringify(event, jsonReplacer)}\n`;
  }
}
