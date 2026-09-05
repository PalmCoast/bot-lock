#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createBotLockServer } from "./server.js";
import { defaultHome } from "./store.js";

const server = createBotLockServer(defaultHome());
const transport = new StdioServerTransport();
await server.connect(transport);