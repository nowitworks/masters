var gulp = require("gulp");
var ts = require("gulp-typescript");
var tsProject = ts.createProject("tsconfig.json");

gulp.task("node", function () {
    return tsProject.src()
        .pipe(tsProject())
        .pipe(gulp.dest("dist"));
});

var tslint = require("gulp-tslint");
 
gulp.task("lint", () =>
    tsProject.src()
        .pipe(tslint({
            formatter: "stylish" //verbose, prose, stylish
        }))
        .pipe(tslint.report())
);

var typedoc = require("gulp-typedoc");

gulp.task("doc", function() {
    return gulp
        .src(["src/linking.ts"])
        .pipe(typedoc({
            module: "commonjs",
            target: "es5",
            out: "docs/",
            name: "linking"
        }))
    ;
});

var browserify = require("browserify");
var source = require("vinyl-source-stream");
var tsify = require("tsify");
var filesToCopy = [
    "node_modules/mcl-wasm/mcl.js",
    "node_modules/mcl-wasm/mcl_c.js",
    "node_modules/mcl-wasm/mcl_c.wasm"
];

gulp.task("copy-files", function () {
    return gulp.src(filesToCopy)
        .pipe(gulp.dest("browser"));
});

gulp.task("make-browser-files", function () {
    return browserify({
        basedir: ".",
        debug: true,
        entries: ["src/index.ts"],
        cache: {},
        packageCache: {},
        standalone: "linking",
        noParse: ["mcl-wasm"]
    })
    .exclude("mcl-wasm")
    .plugin(tsify)
    .bundle()
    .pipe(source("linking.js")) // still needs to have "require("mcl-wasm")" lines removed
    .pipe(gulp.dest("browser"));
});

const rmLines = require('gulp-rm-lines');

gulp.task('remove-requires', function () {
    return gulp.src('./browser/linking.js')
        .pipe(rmLines({
            'filters': [
                /require\(\"mcl-wasm\"\)/
            ]
        }))
        .pipe(gulp.dest('browser'));
});

gulp.task("browser", gulp.series('copy-files', 'make-browser-files', 'remove-requires'));

gulp.task("default", gulp.series('node', 'browser'));
