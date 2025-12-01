// parse-dd-to-ss.js
const fs = require('fs')
const path = require('path')

// 1) อ่านไฟล์ dd.txt (ต้องอยู่โฟลเดอร์เดียวกับไฟล์นี้)
const inputPath = path.join(__dirname, 'shai.txt')
const outputPath = path.join(__dirname, 'shai2.txt')

const input = fs.readFileSync(inputPath, 'utf8').trim()

const lines = input
  .split('\n')
  .map(l => l.trim())
  .filter(Boolean) // ตัดบรรทัดว่าง

// เก็บผลเป็น map: { [packageName]: Set(versions) }
const pkgMap = {}

// loop ทุกบรรทัด
for (const line of lines) {
  // รูปแบบ: ชื่อแพ็กเกจ (v1.2.3, v1.2.4)
  const match = line.match(/^(\S+)\s+\((.+)\)$/)
  if (!match)
    continue

  const name = match[1] // เช่น @everreal/react-charts หรือ github-action-for-generator
  const versionsPart = match[2]

  // แยกเวอร์ชันจากวงเล็บ
  const versions = versionsPart
    .split(',')
    .map(v => v.trim().replace(/^v/, '')) // ตัด v ด้านหน้า => v2.1.27 -> 2.1.27
    .filter(Boolean)

  if (!pkgMap[name])
    pkgMap[name] = new Set()

  // ใส่ลง Set เพื่อกันซ้ำ และรวมกรณีชื่อแพ็กเกจเดียวกันหลายบรรทัด
  versions.forEach(v => pkgMap[name].add(v))
}

// สร้างบรรทัด output
const resultLines = Object.entries(pkgMap).map(([name, versionSet]) => {
  const versionArray = Array.from(versionSet) // ยังเป็น ['2.1.27', '2.1.28', ...]
  const quotedVersions = versionArray.map(v => `'${v}'`)
  return ` '${name}': [${quotedVersions.join(', ')}],`
})

// รวมเป็นข้อความเดียว
const outputText = `${resultLines.join('\n')}\n`

// 2) เขียนลงไฟล์ ss.txt (ทับทุกครั้ง)
fs.writeFileSync(outputPath, outputText, 'utf8')

console.log('✅ แปลงเสร็จแล้ว เขียนผลลัพธ์ลง ss.txt เรียบร้อย')
