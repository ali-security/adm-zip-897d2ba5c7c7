"use strict";

const { expect } = require("chai");
const pth = require("path");
const fs = require("fs");
const rimraf = require("rimraf");
const Zip = require("../adm-zip");
const Utils = require("../util");

// Regression tests for CVE-2026-76845 (CWE-59, Link Following).
//
// sanitize() only checks the textual entry path against the extraction root. A
// symlink that already exists inside the root (planted in a shared, reused or
// predictable extraction directory) still let open()/mkdir() follow it, so an
// archive without any "../" could write or create files outside the root.
// Extraction must now refuse to write through such a symlink.

const isWin = process.platform === "win32";

describe("adm-zip - extraction through pre-existing symlinks (CVE-2026-76845)", () => {
    const base = pth.join(__dirname, "xxx-symlink");
    const root = pth.join(base, "root");
    const outside = pth.join(base, "outside");

    // directory links: junctions need no extra privileges on Windows
    const linkDir = (target, linkPath) => {
        try {
            fs.symlinkSync(pth.resolve(target), linkPath, isWin ? "junction" : "dir");
            return true;
        } catch (e) {
            return false;
        }
    };

    // file links: may need elevated privileges / developer mode on Windows
    const linkFile = (target, linkPath) => {
        try {
            fs.symlinkSync(pth.resolve(target), linkPath, "file");
            return true;
        } catch (e) {
            return false;
        }
    };

    const makeZip = (entries) => {
        const src = new Zip();
        entries.forEach((e) => src.addFile(e.name, e.content === undefined ? null : Buffer.from(e.content)));
        return new Zip(src.toBuffer());
    };

    const expectRejected = (promise) =>
        promise.then(
            () => {
                throw new Error("extraction should have been rejected");
            },
            (err) => err
        );

    beforeEach(() => {
        fs.mkdirSync(root, { recursive: true });
        fs.mkdirSync(outside, { recursive: true });
    });

    afterEach((done) => rimraf(base, done));

    describe("extractAllTo()", () => {
        it("refuses to write a file through a directory symlink inside the target", function () {
            if (!linkDir(outside, pth.join(root, "link"))) this.skip();
            const zip = makeZip([{ name: "link/pwned.txt", content: "pwned" }]);

            expect(() => zip.extractAllTo(root)).to.throw(/There is a file in the way/);
            expect(fs.existsSync(pth.join(outside, "pwned.txt"))).to.be.false;
        });

        it("refuses to overwrite the target of a file symlink inside the target", function () {
            const secret = pth.join(outside, "secret.txt");
            fs.writeFileSync(secret, "original");
            if (!linkFile(secret, pth.join(root, "victim.txt"))) this.skip();
            const zip = makeZip([{ name: "victim.txt", content: "pwned" }]);

            expect(() => zip.extractAllTo(root, true)).to.throw(/There is a file in the way/);
            expect(fs.readFileSync(secret, "utf8")).to.equal("original");
        });

        it("refuses to create a file through a dangling symlink inside the target", function () {
            const created = pth.join(outside, "created.txt");
            if (!linkFile(created, pth.join(root, "new.txt"))) this.skip();
            const zip = makeZip([{ name: "new.txt", content: "pwned" }]);

            expect(() => zip.extractAllTo(root, false)).to.throw(/There is a file in the way/);
            expect(fs.existsSync(created)).to.be.false;
        });

        it("refuses to create a directory through a directory symlink inside the target", function () {
            if (!linkDir(outside, pth.join(root, "link"))) this.skip();
            const zip = makeZip([{ name: "link/sub/" }]);

            expect(() => zip.extractAllTo(root)).to.throw(/There is a file in the way/);
            expect(fs.existsSync(pth.join(outside, "sub"))).to.be.false;
        });

        it("still extracts when the target folder itself is reached through a symlink", function () {
            const real = pth.join(base, "real");
            fs.mkdirSync(real, { recursive: true });
            const rootLink = pth.join(base, "rootlink");
            if (!linkDir(real, rootLink)) this.skip();
            const zip = makeZip([
                { name: "a.txt", content: "a" },
                { name: "sub/b.txt", content: "b" }
            ]);

            zip.extractAllTo(rootLink, true);
            expect(fs.readFileSync(pth.join(real, "a.txt"), "utf8")).to.equal("a");
            expect(fs.readFileSync(pth.join(real, "sub", "b.txt"), "utf8")).to.equal("b");
        });

        it("still extracts into existing real folders inside the target", () => {
            fs.mkdirSync(pth.join(root, "sub"), { recursive: true });
            const zip = makeZip([
                { name: "sub/", content: undefined },
                { name: "sub/c.txt", content: "c" }
            ]);

            zip.extractAllTo(root, true);
            expect(fs.readFileSync(pth.join(root, "sub", "c.txt"), "utf8")).to.equal("c");
        });
    });

    describe("extractEntryTo()", () => {
        it("refuses to write a file entry through a directory symlink inside the target", function () {
            if (!linkDir(outside, pth.join(root, "link"))) this.skip();
            const zip = makeZip([{ name: "link/pwned.txt", content: "pwned" }]);

            expect(() => zip.extractEntryTo("link/pwned.txt", root, true, true)).to.throw(/There is a file in the way/);
            expect(fs.existsSync(pth.join(outside, "pwned.txt"))).to.be.false;
        });

        it("refuses to write through a symlink named by outFileName", function () {
            if (!linkDir(outside, pth.join(root, "link"))) this.skip();
            const zip = makeZip([{ name: "a.txt", content: "pwned" }]);

            expect(() => zip.extractEntryTo("a.txt", root, false, true, false, "link/pwned.txt")).to.throw(/There is a file in the way/);
            expect(fs.existsSync(pth.join(outside, "pwned.txt"))).to.be.false;
        });

        it("refuses to overwrite the target of a file symlink when the entry path is flattened", function () {
            const secret = pth.join(outside, "secret.txt");
            fs.writeFileSync(secret, "original");
            if (!linkFile(secret, pth.join(root, "victim.txt"))) this.skip();
            const zip = makeZip([{ name: "deep/dir/victim.txt", content: "pwned" }]);

            expect(() => zip.extractEntryTo("deep/dir/victim.txt", root, false, true)).to.throw(/There is a file in the way/);
            expect(fs.readFileSync(secret, "utf8")).to.equal("original");
        });

        it("refuses to write the children of a folder entry through a directory symlink", function () {
            if (!linkDir(outside, pth.join(root, "dir"))) this.skip();
            const zip = makeZip([{ name: "dir/" }, { name: "dir/pwned.txt", content: "pwned" }]);

            expect(() => zip.extractEntryTo("dir/", root, true, true)).to.throw(/There is a file in the way/);
            expect(fs.existsSync(pth.join(outside, "pwned.txt"))).to.be.false;
        });
    });

    describe("extractAllToAsync()", () => {
        it("refuses to write a file through a directory symlink inside the target", function () {
            if (!linkDir(outside, pth.join(root, "link"))) this.skip();
            const zip = makeZip([{ name: "link/pwned.txt", content: "pwned" }]);

            return expectRejected(zip.extractAllToAsync(root, true)).then((err) => {
                expect(err.message).to.match(/There is a file in the way/);
                expect(fs.existsSync(pth.join(outside, "pwned.txt"))).to.be.false;
            });
        });

        it("refuses to overwrite the target of a file symlink inside the target", function () {
            const secret = pth.join(outside, "secret.txt");
            fs.writeFileSync(secret, "original");
            if (!linkFile(secret, pth.join(root, "victim.txt"))) this.skip();
            const zip = makeZip([{ name: "victim.txt", content: "pwned" }]);

            return expectRejected(zip.extractAllToAsync(root, true)).then((err) => {
                expect(err.message).to.match(/There is a file in the way/);
                expect(fs.readFileSync(secret, "utf8")).to.equal("original");
            });
        });

        it("refuses to create a directory through a directory symlink inside the target", function () {
            if (!linkDir(outside, pth.join(root, "link"))) this.skip();
            const zip = makeZip([{ name: "link/sub/" }]);

            return expectRejected(zip.extractAllToAsync(root, true)).then((err) => {
                expect(err.message).to.match(/Unable to create folder/);
                expect(fs.existsSync(pth.join(outside, "sub"))).to.be.false;
            });
        });

        it("still extracts when the target folder itself is reached through a symlink", function () {
            const real = pth.join(base, "real");
            fs.mkdirSync(real, { recursive: true });
            const rootLink = pth.join(base, "rootlink");
            if (!linkDir(real, rootLink)) this.skip();
            const zip = makeZip([
                { name: "sub/", content: undefined },
                { name: "sub/b.txt", content: "b" }
            ]);

            return zip.extractAllToAsync(rootLink, true).then(() => {
                expect(fs.readFileSync(pth.join(real, "sub", "b.txt"), "utf8")).to.equal("b");
            });
        });
    });

    describe("Utils.assertPathSafe()", () => {
        it("rejects a symlinked path component below the root", function () {
            if (!linkDir(outside, pth.join(root, "link"))) this.skip();
            const utils = new Utils();

            expect(() => utils.assertPathSafe(root, pth.join(root, "link", "a", "b.txt"))).to.throw(/There is a file in the way/);
        });

        it("accepts the root itself, missing paths and paths outside the root", () => {
            const utils = new Utils();

            expect(() => utils.assertPathSafe(root, root)).to.not.throw();
            expect(() => utils.assertPathSafe(root, pth.join(root, "missing", "file.txt"))).to.not.throw();
            expect(() => utils.assertPathSafe(root, pth.join(outside, "file.txt"))).to.not.throw();
        });

        it("is a no-op for a custom fs without lstatSync", () => {
            const customFs = Object.assign({}, fs);
            delete customFs.lstatSync;
            const utils = new Utils({ fs: customFs });

            expect(() => utils.assertPathSafe(root, pth.join(root, "a.txt"))).to.not.throw();
        });
    });
});
