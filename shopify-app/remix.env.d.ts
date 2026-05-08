/// <reference types="@remix-run/node" />
/// <reference types="@remix-run/react" />
/// <reference types="vite/client" />

// Vite's `?url` suffix returns the asset URL as a string. Used for Polaris CSS.
declare module '*.css?url' {
  const url: string;
  export default url;
}
