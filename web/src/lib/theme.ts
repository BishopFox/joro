/** Returns the active theme name (reads from the document attribute set at startup). */
export function currentTheme(): string {
  return document.documentElement.getAttribute('data-theme') || 'bishop-fox'
}
