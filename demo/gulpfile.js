var gulp = require("gulp");

var filesToCopy = [
    "node_modules/ps-credentials/browser/*",
    "node_modules/linking/browser/*"
];

gulp.task("browser-files", function () {
    return gulp.src(filesToCopy)
        .pipe(gulp.dest("cred/files"));
});

gulp.task("default", gulp.series("browser-files"));
