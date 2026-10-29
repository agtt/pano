import { describe, expect, test } from "bun:test";
import {
  ONDREJ_FINGERPRINT, assertSupported, cliFor, debOptionalPackages, debRequiredPackages, distroFpmUnit, elPackages, fpmBinFor,
  gpgFingerprints, installedDebPackages, mysqlSocketFor, ondrejSources, parseOs, phpRootFor, suryList,
} from "../src/agent/php-os.ts";

const alma = parseOs('NAME="AlmaLinux"\nVERSION_ID="9.4"\nID="almalinux"\nID_LIKE="rhel centos fedora"\n');
const debian = parseOs('PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nVERSION_ID="12"\nVERSION_CODENAME=bookworm\nID=debian\n');
const ubuntu = parseOs('NAME="Ubuntu"\nVERSION_ID="24.04"\nVERSION_CODENAME=noble\nID=ubuntu\nID_LIKE=debian\n');

describe("php-os: detection", () => {
  test("families and codenames", () => {
    expect(alma).toMatchObject({ family: "el", version: "9.4", known: true });
    expect(debian).toMatchObject({ family: "debian", id: "debian", version: "12", codename: "bookworm" });
    expect(ubuntu).toMatchObject({ family: "debian", id: "ubuntu", version: "24.04", codename: "noble" });
    expect(parseOs("")).toMatchObject({ family: "el", known: false });
  });

  test("supported releases", () => {
    expect(() => assertSupported(alma)).not.toThrow();
    expect(() => assertSupported(debian)).not.toThrow();
    expect(() => assertSupported(ubuntu)).not.toThrow();
    expect(() => assertSupported(parseOs("ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"18.04\"\nVERSION_CODENAME=bionic\n"))).toThrow(/not supported/);
    expect(() => assertSupported(parseOs("ID=alpine\nVERSION_ID=3.20\n"))).toThrow(/AlmaLinux/);
    expect(() => assertSupported(parseOs("ID=fedora\nID_LIKE=\"rhel fedora\"\nVERSION_ID=41\n"))).toThrow(/AlmaLinux/);
  });
});

describe("php-os: paths", () => {
  test("EL keeps the Remi layout", () => {
    expect(phpRootFor(alma, "8.3")).toBe("/opt/remi/php83/root");
    expect(fpmBinFor(alma, "8.3")).toBe("/opt/remi/php83/root/usr/sbin/php-fpm");
    expect(cliFor(alma, "8.3")).toBe("/opt/remi/php83/root/usr/bin/php");
    expect(distroFpmUnit(alma, "8.3")).toBe("php83-php-fpm");
    expect(mysqlSocketFor(alma)).toBe("/var/lib/mysql/mysql.sock");
  });

  test("Debian family uses phpX.Y under /usr", () => {
    for (const os of [debian, ubuntu]) {
      expect(fpmBinFor(os, "8.4")).toBe("/usr/sbin/php-fpm8.4");
      expect(cliFor(os, "8.4")).toBe("/usr/bin/php8.4");
      expect(distroFpmUnit(os, "8.4")).toBe("php8.4-fpm");
      expect(phpRootFor(os, "8.4")).toBe("/usr/lib/pano/php/8.4");
      expect(mysqlSocketFor(os)).toBe("/run/mysqld/mysqld.sock");
    }
  });
});

describe("php-os: packages", () => {
  test("EL list is unchanged", () => {
    expect(elPackages("8.2")).toEqual([
      "php82-php-fpm", "php82-php-cli", "php82-php-common", "php82-php-mysqlnd", "php82-php-opcache", "php82-php-gd", "php82-php-intl",
      "php82-php-mbstring", "php82-php-xml", "php82-php-sodium", "php82-php-bcmath", "php82-php-pecl-zip",
    ]);
  });

  test("Debian packages", () => {
    const req = debRequiredPackages("8.3");
    for (const p of ["php8.3-fpm", "php8.3-cli", "php8.3-mysql", "php8.3-curl", "php8.3-gd", "php8.3-mbstring", "php8.3-xml", "php8.3-zip", "php8.3-intl", "php8.3-bcmath"]) {
      expect(req).toContain(p);
    }
    expect(debOptionalPackages("8.3")).toEqual(["php8.3-opcache", "php8.3-redis", "php8.3-imagick"]);
  });

  test("installed packages come from dpkg-query status", () => {
    const out = "php8.3-fpm ii \nphp8.3-cli ii \nphp8.3-redis rc \nphp8.30-foo ii \nphp8.4-fpm ii \nphp8.3-common ii \n";
    expect(installedDebPackages(out, "8.3")).toEqual(["php8.3-fpm", "php8.3-cli", "php8.3-common"]);
    expect(installedDebPackages("", "8.3")).toEqual([]);
  });
});

describe("php-os: repositories", () => {
  test("apt entries", () => {
    expect(suryList("bookworm")).toContain("deb [signed-by=/usr/share/keyrings/deb.sury.org-php.gpg] https://packages.sury.org/php/ bookworm main");
    const src = ondrejSources("noble");
    expect(src).toContain("Suites: noble");
    expect(src).toContain("Signed-By: /usr/share/keyrings/ondrej-php.gpg");
  });

  test("fingerprint parsing takes primary keys only", () => {
    const colons = [
      "pub:-:4096:1:4F4EA0AAE5267A6C:1:::-:::scESC::::::23::0:",
      `fpr:::::::::${ONDREJ_FINGERPRINT}:`,
      "uid:-::::1::HASH::Launchpad PPA for Ondřej Surý::::::::::0:",
      "sub:-:4096:1:AAAAAAAAAAAAAAAA:1::::::e::::::23:",
      "fpr:::::::::0123456789ABCDEF0123456789ABCDEF01234567:",
    ].join("\n");
    expect(gpgFingerprints(colons)).toEqual([ONDREJ_FINGERPRINT]);
    expect(gpgFingerprints("")).toEqual([]);
  });
});
