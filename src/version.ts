/** The app's version, from package.json at build time. */
export const APP_VERSION: string = __APP_VERSION__;

/** The release's name, for the moments the app introduces itself. */
export const RELEASE_NAME = "Thunderbolt";

/** "2.0" from "2.0.3": what a release note is about. */
export const RELEASE_LINE = APP_VERSION.split(".").slice(0, 2).join(".");
