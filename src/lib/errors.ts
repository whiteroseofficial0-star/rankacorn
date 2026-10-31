/**
 * An upstream provider (PageSpeed, RDAP, ...) returned a message that is safe
 * to show to the user as-is. Other uncaught errors stay generic so internal
 * details are never reflected back to the browser.
 */
export class ProviderError extends Error {}
