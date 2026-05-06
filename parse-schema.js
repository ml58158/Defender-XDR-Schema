const fs = require("fs");
const path = require("path");

const baseDir = __dirname;
const inputDir = path.join(baseDir, "schema", "raw-md");
const outputDir = path.join(baseDir, "schema", "parsed-json");

if (!fs.existsSync(inputDir)) {
    console.error("Raw schema folder not found:", inputDir);
    process.exit(1);
}

fs.readdirSync(inputDir).forEach(file => {
    const content = fs.readFileSync(path.join(inputDir, file), "utf8");

    const match = file.match(/advanced-hunting-(.*)-table.md/);
    if (!match) return;

    const tableName = match[1];

    const rows = [...content.matchAll(/\|\s*([\w]+)\s*\|\s*([\w]+)\s*\|\s*(.*?)\s*\|/g)];

    const columns = rows.map(r => ({
        name: r[1],
        type: r[2],
        description: r[3]
    }));

    fs.writeFileSync(
        path.join(outputDir, tableName + ".json"),
        JSON.stringify({ table: tableName, columns }, null, 2)
    );
});
