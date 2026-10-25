"use strict";

const { expect } = require("chai");
const pth = require("path");
const fs = require("fs");
const zlib = require("zlib");
const rimraf = require("rimraf");
const Zip = require("../adm-zip");
const Utils = require("../util");
const Inflater = require("../methods").Inflater;

// Regression tests for decompression bombs that lie about their uncompressed size
// (CWE-409, Improper Handling of Highly Compressed Data).
//
// The inflater caps its output at the entry's declared uncompressed size. That
// cap used to be dropped when the declared size was 0, and the async (streaming)
// path never enforced it at all, so a tiny archive could still be inflated to an
// arbitrarily large buffer. Both paths must now refuse to produce more than the
// declared number of bytes.

const nodeMajor = +(process.versions ? process.versions.node : "").split(".")[0] || 0;
// The sync path relies on zlib's maxOutputLength, which the inflater only passes
// on Node >= 15; the async path enforces the cap by itself on every version.
const syncCapSupported = nodeMajor >= 15;

const PAYLOAD_SIZE = 4 * 1024 * 1024; // 4 MiB of a single byte value
const payload = Buffer.alloc(PAYLOAD_SIZE, 0x41);
const deflatedPayload = zlib.deflateRawSync(payload);

const u16 = (n) => {
    const b = Buffer.alloc(2);
    b.writeUInt16LE(n >>> 0);
    return b;
};
const u32 = (n) => {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(n >>> 0);
    return b;
};

// Build a single-entry DEFLATED zip whose compressed data and CRC are valid for
// `content`, but whose local and central headers declare `declaredSize` bytes.
function craftZip(content, declaredSize) {
    const name = Buffer.from("bomb.txt");
    const compressed = zlib.deflateRawSync(content);
    const crc = Utils.crc32(content);
    const dosTime = 0;
    const dosDate = ((2024 - 1980) << 9) | (1 << 5) | 1; // 2024-01-01
    const lfh = Buffer.concat([
        u32(0x04034b50),
        u16(20),
        u16(0),
        u16(8),
        u16(dosTime),
        u16(dosDate),
        u32(crc),
        u32(compressed.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        name,
        compressed
    ]);
    const cd = Buffer.concat([
        u32(0x02014b50),
        u16(20),
        u16(20),
        u16(0),
        u16(8),
        u16(dosTime),
        u16(dosDate),
        u32(crc),
        u32(compressed.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        u16(0),
        u16(0),
        u16(0),
        u32(0),
        u32(0),
        name
    ]);
    const eocd = Buffer.concat([u32(0x06054b50), u16(0), u16(0), u16(1), u16(1), u32(cd.length), u32(lfh.length), u16(0)]);
    return Buffer.concat([lfh, cd, eocd]);
}

describe("adm-zip - decompression bomb - declared size cap", () => {
    describe("methods/inflater", () => {
        it("inflateAsync() refuses to inflate past a declared size of 0", (done) => {
            new Inflater(deflatedPayload, 0).inflateAsync(function (data, err) {
                expect(err, "an error must be reported").to.be.an("error");
                expect(err.message).to.match(/exceeds the declared uncompressed size/);
                expect(data.length).to.equal(0);
                done();
            });
        });

        it("inflateAsync() refuses to inflate past an undersized declared size", (done) => {
            new Inflater(deflatedPayload, 16).inflateAsync(function (data, err) {
                expect(err, "an error must be reported").to.be.an("error");
                expect(err.message).to.match(/exceeds the declared uncompressed size/);
                expect(data.length).to.equal(0);
                done();
            });
        });

        it("inflateAsync() reports the error only once", (done) => {
            let calls = 0;
            new Inflater(deflatedPayload, 0).inflateAsync(function (data, err) {
                calls++;
                expect(err).to.be.an("error");
            });
            setTimeout(() => {
                expect(calls).to.equal(1);
                done();
            }, 200);
        });

        it("inflate() refuses to inflate past a declared size of 0", function () {
            if (!syncCapSupported) this.skip(); // maxOutputLength is only applied on Node >= 15
            expect(() => new Inflater(deflatedPayload, 0).inflate()).to.throw(RangeError);
        });

        it("inflate() refuses to inflate past an undersized declared size", function () {
            if (!syncCapSupported) this.skip(); // maxOutputLength is only applied on Node >= 15
            expect(() => new Inflater(deflatedPayload, 16).inflate()).to.throw(RangeError);
        });

        it("still inflates a genuinely empty entry declared as 0 bytes", (done) => {
            const empty = zlib.deflateRawSync(Buffer.alloc(0));
            expect(new Inflater(empty, 0).inflate().length).to.equal(0);
            new Inflater(empty, 0).inflateAsync(function (data, err) {
                expect(err).to.equal(undefined);
                expect(data.length).to.equal(0);
                done();
            });
        });

        it("still inflates an entry whose declared size is honest", (done) => {
            expect(new Inflater(deflatedPayload, PAYLOAD_SIZE).inflate().equals(payload)).to.equal(true);
            new Inflater(deflatedPayload, PAYLOAD_SIZE).inflateAsync(function (data, err) {
                expect(err).to.equal(undefined);
                expect(data.equals(payload)).to.equal(true);
                done();
            });
        });
    });

    describe("zip entries", () => {
        const destination = pth.join(__dirname, "xxx_size_cap");

        afterEach((done) => rimraf(destination, done));

        it("getDataAsync() rejects a bomb that declares a size of 0", (done) => {
            const zip = new Zip(craftZip(payload, 0));
            zip.getEntries()[0].getDataAsync(function (data, err) {
                expect(err, "an error must be reported").to.be.an("error");
                expect(err.message).to.match(/exceeds the declared uncompressed size/);
                expect(data.length).to.equal(0);
                done();
            });
        });

        it("getDataAsync() rejects a bomb that declares an undersized size", (done) => {
            const zip = new Zip(craftZip(payload, 1));
            zip.getEntries()[0].getDataAsync(function (data, err) {
                expect(err, "an error must be reported").to.be.an("error");
                expect(err.message).to.match(/exceeds the declared uncompressed size/);
                expect(data.length).to.equal(0);
                done();
            });
        });

        it("readFileAsync() and readAsTextAsync() reject a bomb that declares a size of 0", (done) => {
            const zip = new Zip(craftZip(payload, 0));
            zip.readFileAsync("bomb.txt", function (data, err) {
                expect(err, "readFileAsync must report an error").to.be.an("error");
                expect(data.length).to.equal(0);
                zip.readAsTextAsync("bomb.txt", function (text, err2) {
                    expect(err2, "readAsTextAsync must report an error").to.be.an("error");
                    expect(text.length).to.equal(0);
                    done();
                });
            });
        });

        it("extractAllToAsync() rejects a bomb that declares a size of 0", (done) => {
            const zip = new Zip(craftZip(payload, 0));
            zip.extractAllToAsync(destination, true, false, function (err) {
                expect(err, "an error must be reported").to.be.an("error");
                expect(fs.existsSync(pth.join(destination, "bomb.txt"))).to.equal(false);
                done();
            });
        });

        it("getData() rejects a bomb that declares a size of 0 before inflating it", function () {
            if (!syncCapSupported) this.skip(); // maxOutputLength is only applied on Node >= 15
            const zip = new Zip(craftZip(payload, 0));
            // Without the cap the whole payload is inflated and only then rejected by
            // the CRC check; with it zlib aborts as soon as the output passes the cap.
            expect(() => zip.getEntries()[0].getData()).to.throw(RangeError);
        });

        it("still reads a legitimate DEFLATED entry", (done) => {
            const zip = new Zip(craftZip(payload, PAYLOAD_SIZE));
            expect(zip.readFile("bomb.txt").equals(payload)).to.equal(true);
            zip.getEntries()[0].getDataAsync(function (data, err) {
                expect(err).to.equal(undefined);
                expect(data.equals(payload)).to.equal(true);
                done();
            });
        });

        it("still reads a legitimate entry written by adm-zip", (done) => {
            const zip = new Zip();
            const content = Buffer.from("hello world ".repeat(5000));
            zip.addFile("d.txt", content);
            const round = new Zip(zip.toBuffer());
            expect(round.readFile("d.txt").equals(content)).to.equal(true);
            round.readFileAsync("d.txt", function (data, err) {
                expect(err).to.equal(undefined);
                expect(data.equals(content)).to.equal(true);
                done();
            });
        });
    });
});
