#!/usr/bin/env swift
// Generates Apps/macOS/AppIcon.icns.
//
// Drawn in code rather than checked in as a binary so it can be changed by
// editing three colours instead of opening a design tool. Deliberately plain:
// a shield on a gradient, which reads at 16pt in the menu bar and at 512pt in
// the Finder without any detail to lose in between.
//
//   swift Tools/make-icon.swift

import AppKit
import ImageIO
import UniformTypeIdentifiers
import CoreGraphics
import Foundation

let outputDir = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
    .appendingPathComponent("Apps/macOS")
let iconset = outputDir.appendingPathComponent("AppIcon.iconset")

try? FileManager.default.removeItem(at: iconset)
try FileManager.default.createDirectory(at: iconset, withIntermediateDirectories: true)

// Deep blue to teal: distinct from the system blue every other VPN client uses.
let topColor = CGColor(red: 0.10, green: 0.22, blue: 0.44, alpha: 1)
let bottomColor = CGColor(red: 0.06, green: 0.52, blue: 0.55, alpha: 1)

func drawIcon(size: Int) -> CGImage? {
    let s = CGFloat(size)
    guard let ctx = CGContext(data: nil, width: size, height: size,
                              bitsPerComponent: 8, bytesPerRow: 0,
                              space: CGColorSpaceCreateDeviceRGB(),
                              bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)
    else { return nil }

    ctx.setAllowsAntialiasing(true)
    ctx.interpolationQuality = .high

    // macOS icons sit in a rounded square with a margin; roughly matching the
    // system metric keeps it from looking oversized next to stock apps.
    let inset = s * 0.06
    let rect = CGRect(x: inset, y: inset, width: s - inset * 2, height: s - inset * 2)
    let squircle = CGPath(roundedRect: rect,
                          cornerWidth: rect.width * 0.2237,
                          cornerHeight: rect.height * 0.2237,
                          transform: nil)

    ctx.saveGState()
    ctx.addPath(squircle)
    ctx.clip()
    if let gradient = CGGradient(colorsSpace: CGColorSpaceCreateDeviceRGB(),
                                 colors: [topColor, bottomColor] as CFArray,
                                 locations: [0, 1]) {
        ctx.drawLinearGradient(gradient,
                               start: CGPoint(x: 0, y: s),
                               end: CGPoint(x: s, y: 0),
                               options: [])
    }
    ctx.restoreGState()

    // Shield.
    let w = rect.width
    let cx = rect.midX
    let shieldW = w * 0.46
    let shieldH = w * 0.56
    let top = rect.midY + shieldH * 0.5
    let bottom = rect.midY - shieldH * 0.5

    let shield = CGMutablePath()
    shield.move(to: CGPoint(x: cx, y: top))
    shield.addLine(to: CGPoint(x: cx + shieldW / 2, y: top - shieldH * 0.26))
    shield.addLine(to: CGPoint(x: cx + shieldW / 2, y: bottom + shieldH * 0.30))
    shield.addQuadCurve(to: CGPoint(x: cx, y: bottom),
                        control: CGPoint(x: cx + shieldW * 0.44, y: bottom + shieldH * 0.06))
    shield.addQuadCurve(to: CGPoint(x: cx - shieldW / 2, y: bottom + shieldH * 0.30),
                        control: CGPoint(x: cx - shieldW * 0.44, y: bottom + shieldH * 0.06))
    shield.addLine(to: CGPoint(x: cx - shieldW / 2, y: top - shieldH * 0.26))
    shield.closeSubpath()

    ctx.setFillColor(CGColor(red: 1, green: 1, blue: 1, alpha: 0.95))
    ctx.addPath(shield)
    ctx.fillPath()

    // A rounded slot cut through the shield, reading as a tunnel mouth. Square
    // ends and full width made it read as a minus sign — "disabled" — which is
    // the opposite of what a VPN icon should say.
    ctx.setBlendMode(.clear)
    let barH = shieldH * 0.115
    let barW = shieldW * 0.42
    ctx.addPath(CGPath(roundedRect: CGRect(x: cx - barW / 2, y: rect.midY - barH / 2,
                                           width: barW, height: barH),
                       cornerWidth: barH / 2, cornerHeight: barH / 2, transform: nil))
    ctx.fillPath()
    ctx.setBlendMode(.normal)

    return ctx.makeImage()
}

// The sizes `iconutil` expects.
let variants: [(name: String, size: Int)] = [
    ("icon_16x16", 16), ("icon_16x16@2x", 32),
    ("icon_32x32", 32), ("icon_32x32@2x", 64),
    ("icon_128x128", 128), ("icon_128x128@2x", 256),
    ("icon_256x256", 256), ("icon_256x256@2x", 512),
    ("icon_512x512", 512), ("icon_512x512@2x", 1024),
]

for variant in variants {
    guard let image = drawIcon(size: variant.size) else {
        FileHandle.standardError.write(Data("failed at \(variant.name)\n".utf8))
        exit(1)
    }
    let url = iconset.appendingPathComponent("\(variant.name).png")
    guard let dest = CGImageDestinationCreateWithURL(url as CFURL, "public.png" as CFString, 1, nil)
    else { exit(1) }
    CGImageDestinationAddImage(dest, image, nil)
    CGImageDestinationFinalize(dest)
}

let convert = Process()
convert.executableURL = URL(fileURLWithPath: "/usr/bin/iconutil")
convert.arguments = ["-c", "icns", iconset.path,
                     "-o", outputDir.appendingPathComponent("AppIcon.icns").path]
try convert.run()
convert.waitUntilExit()
guard convert.terminationStatus == 0 else { exit(convert.terminationStatus) }

try? FileManager.default.removeItem(at: iconset)
print("wrote \(outputDir.appendingPathComponent("AppIcon.icns").path)")
