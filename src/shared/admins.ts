// Rules for managing admins, shared by the agent (which enforces them) and the
// web (which checks early to give a clear message). All admins are equal: there
// are no roles.

export const USERNAME_RE = /^[a-z][a-z0-9_.-]{2,31}$/;

export function checkUsername(username: string) {
  if (!USERNAME_RE.test(username)) throw new Error("username: 3-32 lowercase chars (a-z, 0-9, _ . -), starting with a letter");
}

/** Nobody removes themselves or the last admin; `admins` is everyone who can sign in now. */
export function checkRemove(actor: string, target: string, admins: string[]) {
  if (!admins.includes(target)) throw new Error("no such admin");
  if (target === actor) throw new Error("you cannot remove yourself: ask another admin");
  if (admins.length <= 1) throw new Error("you cannot remove the last admin");
}
