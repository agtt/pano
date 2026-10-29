// What differs per OS family for PHP: package names, binary and config paths,
// the package repository. AlmaLinux/Rocky/RHEL use Remi (one directory per
// minor under /opt/remi); Debian and Ubuntu use Ondřej Surý's repository
// (packages.sury.org / ppa:ondrej/php, phpX.Y-* packages under /usr). Pure
// functions only; php.ts does the installing.

import { readFileSync } from "node:fs";
import { fsPath } from "../shared/config.ts";

export type PhpOs = { family: "el" | "debian"; id: string; version: string; codename: string; known: boolean };

const EL_ID = /^(ID|ID_LIKE)=.*\b(rhel|centos|fedora|almalinux|rocky)\b/m;
const DEB_ID = /^(ID|ID_LIKE)=.*\b(debian|ubuntu)\b/m;

/** Suites Surý's repositories publish PHP for; anything else is refused with a clear message. */
const DEBIAN_CODENAMES: Record<string, string> = { "11": "bullseye", "12": "bookworm", "13": "trixie" };
const UBUNTU_CODENAMES: Record<string, string> = { "22.04": "jammy", "24.04": "noble" };

const field = (text: string, key: string) => text.match(new RegExp(`^${key}=("?)([^"\\n]*)\\1$`, "m"))?.[2] ?? "";

/** Family and release from /etc/os-release. Unknown systems count as EL (the original behaviour). */
export function parseOs(text: string): PhpOs {
  const id = field(text, "ID");
  const version = field(text, "VERSION_ID");
  const deb = DEB_ID.test(text) && !EL_ID.test(text);
  const codename = deb ? field(text, "VERSION_CODENAME") || (id === "ubuntu" ? UBUNTU_CODENAMES[version] : DEBIAN_CODENAMES[version]) || "" : "";
  return { family: deb ? "debian" : "el", id, version, codename, known: deb || EL_ID.test(text) };
}

let cached: PhpOs | undefined;
/** Synchronous (path helpers are); the OS does not change while the agent runs. */
export function currentOs(): PhpOs {
  if (!cached) {
    let text = "";
    try {
      text = readFileSync(fsPath("/etc/os-release"), "utf8");
    } catch {}
    cached = parseOs(text);
  }
  return cached;
}
/** For tests. */
export const resetOsCache = () => { cached = undefined; };

/** Throws unless this release is one PHP can be installed on. */
export function assertSupported(os: PhpOs): void {
  if (os.family === "el") {
    if (!os.known || !["8", "9", "10"].includes(os.version.split(".")[0] ?? "")) {
      throw new Error("PHP sites currently need AlmaLinux, Rocky or RHEL 8-10 (Remi packages), Debian 11-13 or Ubuntu 22.04/24.04 (Sury packages)");
    }
    return;
  }
  const ok = os.id === "ubuntu" ? os.version in UBUNTU_CODENAMES : os.version in DEBIAN_CODENAMES;
  if (!ok || !os.codename) {
    throw new Error(`PHP sites on ${os.id || "this system"} ${os.version} are not supported (Debian 11-13, Ubuntu 22.04/24.04)`);
  }
}

// ---- paths -------------------------------------------------------------------

const scl = (ver: string) => `php${ver.replace(".", "")}`;
/** Debian: a directory holding usr/bin/php -> /usr/bin/phpX.Y, so cron jobs can put `php` on PATH. */
export const debShimRoot = (ver: string) => `/usr/lib/pano/php/${ver}`;

/** Install root of a PHP minor: the file layout below it is that of a normal /usr tree. */
export const phpRootFor = (os: PhpOs, ver: string) => (os.family === "debian" ? debShimRoot(ver) : `/opt/remi/${scl(ver)}/root`);
export const fpmBinFor = (os: PhpOs, ver: string) => (os.family === "debian" ? `/usr/sbin/php-fpm${ver}` : `/opt/remi/${scl(ver)}/root/usr/sbin/php-fpm`);
export const cliFor = (os: PhpOs, ver: string) => (os.family === "debian" ? `/usr/bin/php${ver}` : `/opt/remi/${scl(ver)}/root/usr/bin/php`);
/** The distribution's own server-wide pool service (pano runs one pool per site instead). */
export const distroFpmUnit = (os: PhpOs, ver: string) => (os.family === "debian" ? `php${ver}-fpm` : `${scl(ver)}-php-fpm`);
/** MariaDB's socket, as the distribution's packages place it. */
export const mysqlSocketFor = (os: PhpOs) => (os.family === "debian" ? "/run/mysqld/mysqld.sock" : "/var/lib/mysql/mysql.sock");

// ---- packages ----------------------------------------------------------------

/** Extensions every site gets; the rest of the common ones (ctype, fileinfo, pdo, sodium, ...) are inside phpX.Y-common. */
const EL_EXTENSIONS = ["fpm", "cli", "common", "mysqlnd", "opcache", "gd", "intl", "mbstring", "xml", "sodium", "bcmath", "pecl-zip"];
const DEB_REQUIRED = ["fpm", "cli", "common", "mysql", "curl", "gd", "intl", "mbstring", "xml", "zip", "bcmath"];
/** Installed one by one when they exist for this version (PHP 8.5 has opcache built in, redis/imagick may lag a new release). */
const DEB_OPTIONAL = ["opcache", "redis", "imagick"];

export function elPackages(ver: string): string[] {
  return EL_EXTENSIONS.map((e) => `${scl(ver)}-php-${e}`);
}
export const debRequiredPackages = (ver: string) => DEB_REQUIRED.map((e) => `php${ver}-${e}`);
export const debOptionalPackages = (ver: string) => DEB_OPTIONAL.map((e) => `php${ver}-${e}`);

/** Installed phpX.Y-* packages out of `dpkg-query -W -f '${Package} ${db:Status-Abbrev}\n'` (only fully installed ones). */
export function installedDebPackages(dpkgOutput: string, ver: string): string[] {
  const prefix = `php${ver}-`;
  const out: string[] = [];
  for (const line of dpkgOutput.split("\n")) {
    const [name, status] = line.trim().split(/\s+/);
    if (name && name.startsWith(prefix) && status?.startsWith("ii")) out.push(name);
  }
  return out;
}

// ---- repositories (Debian family) ---------------------------------------------

export const SURY_KEYRING = "/usr/share/keyrings/deb.sury.org-php.gpg";
export const SURY_KEYRING_DEB = "https://packages.sury.org/debsuryorg-archive-keyring.deb";
export const SURY_LIST = "/etc/apt/sources.list.d/php-sury.list";
/** Signing key of ppa:ondrej/php; the downloaded key must have exactly this fingerprint. */
export const ONDREJ_FINGERPRINT = "14AA40EC0831756756D7F66C4F4EA0AAE5267A6C";
export const ONDREJ_KEY_URL = `https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x${ONDREJ_FINGERPRINT}`;
export const ONDREJ_KEYRING = "/usr/share/keyrings/ondrej-php.gpg";
export const ONDREJ_SOURCES = "/etc/apt/sources.list.d/ondrej-php.sources";

export const suryList = (codename: string) => `# Managed by pano.\ndeb [signed-by=${SURY_KEYRING}] https://packages.sury.org/php/ ${codename} main\n`;

export const ondrejSources = (codename: string) => `# Managed by pano.
Types: deb
URIs: https://ppa.launchpadcontent.net/ondrej/php/ubuntu
Suites: ${codename}
Components: main
Signed-By: ${ONDREJ_KEYRING}
`;

/** Fingerprints in `gpg --show-keys --with-colons` output (the primary keys' `fpr` records). */
export function gpgFingerprints(colons: string): string[] {
  const out: string[] = [];
  let primary = false;
  for (const line of colons.split("\n")) {
    const f = line.split(":");
    if (f[0] === "pub") primary = true;
    else if (f[0] === "sub") primary = false;
    else if (f[0] === "fpr" && primary) {
      out.push((f[9] ?? "").toUpperCase());
      primary = false;
    }
  }
  return out;
}
