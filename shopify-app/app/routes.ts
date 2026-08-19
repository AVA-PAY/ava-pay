import { flatRoutes } from '@react-router/fs-routes';
import type { RouteConfig } from '@react-router/dev/routes';

// Same flat-file convention we used under Remix; route filenames unchanged.
// Test files sit next to the routes they cover, and every file under app/routes
// is a route unless it is ignored here: without the *.test.ts pattern the build
// compiles a vitest file into a browser chunk and fails on its top-level await.
export default flatRoutes({
  ignoredRouteFiles: ['**/.*', '**/*.test.ts', '**/*.test.tsx'],
}) satisfies RouteConfig;
