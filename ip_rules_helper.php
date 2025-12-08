<?php
function getBlockedIPsFromConf($confFile = '/etc/nginx/sites-available/ip_rules.conf') {
    $ips = [];
    if (!is_readable($confFile)) return $ips;
    $lines = file($confFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        if (preg_match('/^deny\s+(\d+\.\d+\.\d+\.\d+);/', trim($line), $m)) {
            $ips[] = $m[1];
        }
    }
    return $ips;
}
function blockIPInConf($ip, $confFile = '/etc/nginx/sites-available/ip_rules.conf') {
    $ips = getBlockedIPsFromConf($confFile);
    if (!in_array($ip, $ips)) {
        file_put_contents($confFile, "deny $ip;\n", FILE_APPEND);
        exec('sudo systemctl reload nginx');
        return true;
    }
    return false;
}
function unblockIPInConf($ip, $confFile = '/etc/nginx/sites-available/ip_rules.conf') {
    if (!is_readable($confFile)) return false;
    $lines = file($confFile);
    $newLines = array_filter($lines, function($line) use ($ip) {
        return !preg_match("/^deny\s+$ip;/", trim($line));
    });
    file_put_contents($confFile, implode("", $newLines));
    exec('sudo systemctl reload nginx');
    return true;
}

