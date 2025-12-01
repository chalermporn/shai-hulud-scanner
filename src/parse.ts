// parse-dd-to-ss.ts
import { join } from 'path'

// 1) อ่านไฟล์ dd.txt (ต้องอยู่โฟลเดอร์เดียวกับไฟล์นี้)
const inputPath = join(import.meta.dir, 'shai.txt')
const outputPath = join(import.meta.dir, 'shai2.txt')

const inputFile = Bun.file(inputPath)
const input = (await inputFile.text()).trim()

const lines: string[] = input
  .split('\n')
  .map(l => l.trim())
  .filter(Boolean) // ตัดบรรทัดว่าง

// เก็บผลเป็น map: { [packageName]: Set(versions) }
const pkgMap: Record<string, Set<string>> = {}

// loop ทุกบรรทัด
for (const line of lines) {
  // รูปแบบ: ชื่อแพ็กเกจ (v1.2.3, v1.2.4)
  const match = line.match(/^(\S+)\s+\((.+)\)$/)
  if (!match)
    continue

  const name: string = match[1]! // เช่น @everreal/react-charts หรือ github-action-for-generator
  const versionsPart: string = match[2]!

  // แยกเวอร์ชันจากวงเล็บ
  const versions: string[] = versionsPart
    .split(',')
    .map(v => v.trim().replace(/^v/, '')) // ตัด v ด้านหน้า => v2.1.27 -> 2.1.27
    .filter(Boolean)

  if (!pkgMap[name])
    pkgMap[name] = new Set<string>()

  // ใส่ลง Set เพื่อกันซ้ำ และรวมกรณีชื่อแพ็กเกจเดียวกันหลายบรรทัด
  versions.forEach(v => pkgMap[name]!.add(v))
}

// สร้างบรรทัด output
const resultLines: string[] = Object.entries(pkgMap).map(([name, versionSet]) => {
  const versionArray: string[] = Array.from(versionSet) // ยังเป็น ['2.1.27', '2.1.28', ...]
  const quotedVersions: string[] = versionArray.map(v => `'${v}'`)
  return ` '${name}': [${quotedVersions.join(', ')}],`
})

// รวมเป็นข้อความเดียว
const outputText: string = `${resultLines.join('\n')}\n`

// 2) เขียนลงไฟล์ ss.txt (ทับทุกครั้ง)
await Bun.write(outputPath, outputText)

console.log('✅ แปลงเสร็จแล้ว เขียนผลลัพธ์ลง shai2.txt เรียบร้อย')
