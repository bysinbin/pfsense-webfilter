<?php
echo "=== Running PHP Syntax Linter on all codebase files ===\n";

$iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator('.'));
$files = [];
foreach ($iterator as $file) {
    if ($file->isFile() && in_array(pathinfo($file->getPathname(), PATHINFO_EXTENSION), ['php', 'inc'])) {
        $files[] = $file->getPathname();
    }
}

sort($files);
$failed = 0;
foreach ($files as $file) {
    $output = [];
    $return_var = 0;
    exec("php -l " . escapeshellarg($file) . " 2>&1", $output, $return_var);
    if ($return_var !== 0) {
        echo "[FAIL] " . $file . "\n";
        echo "       " . implode("\n       ", $output) . "\n";
        $failed++;
    } else {
        echo "[OK]   " . $file . "\n";
    }
}

if ($failed === 0) {
    echo "\nAll " . count($files) . " PHP/INC files passed syntax check with 0 errors!\n";
    exit(0);
} else {
    echo "\n{$failed} files failed syntax check!\n";
    exit(1);
}
