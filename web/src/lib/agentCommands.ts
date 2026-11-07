/** Befehle, die die Agents-Seite anzeigt. Keiner enthält den Token (er stünde sonst in `ps` und der Shell-History). */
export const SET_TOKEN_COMMAND = "sudo patchwatch-agent set-token";

export function installCommand(origin: string, releaseBase: string): string {
  return `curl -fsSL -o install.sh ${releaseBase}/install.sh && sudo sh install.sh --server-url ${origin}`;
}
