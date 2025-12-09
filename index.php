<?php
// index.php – Server 1 Monitoring Dashboard
$accessLog = '/var/log/nginx/access.log';
$ddosLog = __DIR__ . '/ddos-monitor.log';
$blockedIPsFile = __DIR__ . '/blocked-ips.json';
$notesFile = __DIR__ . '/notes.json';
$timeWindow = 7200;
$ddosThreshold = 86400;

if (!file_exists($ddosLog)) {
  file_put_contents($ddosLog, '');
}
if (!file_exists($blockedIPsFile)) {
  file_put_contents($blockedIPsFile, json_encode([]));
}
if (!file_exists($notesFile)) {
  file_put_contents($notesFile, json_encode(new stdClass()));
}

function getTemp()
{
  $zone = '/sys/class/thermal/thermal_zone0/temp';
  if (is_readable($zone)) {
    $m = intval(trim(file_get_contents($zone)));
    return round($m / 1000, 1);
  }
  exec('which sensors', $o, $c);
  if ($c === 0) {
    exec('sensors', $r);
    foreach ($r as $l) {
      if (preg_match('/(?:Package id 0|CPU Temperature):\s+\+([\d\.]+)°C/', $l, $m)) {
        return floatval($m[1]);
      }
    }
  }
  return 'N/A';
}
function getSwap()
{
  $mi = file_get_contents('/proc/meminfo');
  preg_match('/SwapTotal:\s+(\d+)/', $mi, $t);
  preg_match('/SwapFree:\s+(\d+)/', $mi, $f);
  $tot = $t[1] / 1024;
  $used = ($t[1] - $f[1]) / 1024;
  return ['total' => round($tot, 1), 'used' => round($used, 1)];
}
function getUptime()
{
  $u = explode(' ', trim(file_get_contents('/proc/uptime')));
  $s = intval($u[0]);
  return floor($s / 3600) . 'h ' . floor(($s % 3600) / 60) . 'm';
}
function getNetThroughput()
{
  $dev = 'eno2';
  $d1 = file('/proc/net/dev');
  sleep(1);
  $d2 = file('/proc/net/dev');
  foreach ($d1 as $i => $l) {
    if (strpos($l, "$dev:") !== false) {
      $b1 = preg_split('/\s+/', trim($l));
      $b2 = preg_split('/\s+/', trim($d2[$i]));
      $rx = ($b2[1] - $b1[1]) / 1024;
      $tx = ($b2[9] - $b1[9]) / 1024;
      return ['rx' => round($rx, 1), 'tx' => round($tx, 1)];
    }
  }
  return ['rx' => 0, 'tx' => 0];
}
function getServices()
{
  $svc = ['nginx', 'php8.2-fpm', 'mysql'];
  $out = [];
  foreach ($svc as $s) {
    exec("systemctl is-active $s", $o, $c);
    $out[$s] = $c === 0 ? 'running' : 'down';
  }
  return $out;
}
function getTopProcs()
{
  exec("ps axho pcpu,pmem,cmd --sort=-pcpu | head -n5", $o);
  return $o;
}
function getLogSummary()
{
  $log = '/var/log/nginx/error.log';
  if (!file_exists($log))
    return [];
  $lines = array_reverse(file($log));
  return array_slice($lines, 0, 15);
}
function getAccessLogSummary()
{
  $log = '/var/log/nginx/access.log';
  if (!file_exists($log))
    return [];
  $lines = array_reverse(file($log));
  return array_slice($lines, 0, 15);
}

function getActiveSSH()
{
  exec("who | grep 'pts'", $out, $code);
  if ($code !== 0 || empty($out))
    return [];
  $sessions = [];
  function getIPCountry($ip)
  {
    if ($ip === 'N/A' || preg_match('/^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|127\.|::1)/', $ip)) {
      return '';
    }
    static $cache = [];
    if (isset($cache[$ip]))
      return $cache[$ip];
    $country = '';
    $url = "https://ipinfo.io/{$ip}/country";
    $ctx = stream_context_create(['http' => ['timeout' => 2]]);
    $result = @file_get_contents($url, false, $ctx);
    if ($result !== false) {
      $country = trim($result);
    }
    $cache[$ip] = $country;
    return $country;
  }
  foreach ($out as $line) {
    $parts = preg_split('/\s+/', $line);
    $user = isset($parts[0]) ? $parts[0] : '';
    $tty = isset($parts[1]) ? $parts[1] : '';
    $date = isset($parts[2]) ? $parts[2] : '';
    $time = '';
    $timeIndex = null;
    for ($i = 3; $i < count($parts); $i++) {
      if (preg_match('/^\d{1,2}:\d{2}$/', $parts[$i])) {
        $time = $parts[$i];
        $timeIndex = $i;
        break;
      }
    }
    $ip = 'N/A';
    foreach ($parts as $p) {
      if (preg_match('/\((\d+\.\d+\.\d+\.\d+)\)/', $p, $m)) {
        $ip = $m[1];
        break;
      }
    }
    $ipType = '';
    if (preg_match('/^10\.255\.254\.(\d{1,3})$/', $ip, $m) && intval($m[1]) >= 0 && intval($m[1]) <= 255) {
      $ipType = ' (internal)';
    }
    $country = getIPCountry($ip);
    $countryStr = $country ? " [{$country}]" : '';
    if ($user && $tty && $time) {
      $loginTimestamp = false;
      if (preg_match('/^\d{4}-\d{2}-\d{2}$/', $date)) {
        $loginTimestamp = strtotime($date . ' ' . $time);
      } else {
        $month = null;
        $day = null;
        if ($timeIndex !== null) {
          if (isset($parts[$timeIndex - 1]) && preg_match('/^\d{1,2}$/', $parts[$timeIndex - 1])) {
            $day = $parts[$timeIndex - 1];
            if (isset($parts[$timeIndex - 2]) && preg_match('/^[A-Za-z]{3}$/', $parts[$timeIndex - 2])) {
              $month = $parts[$timeIndex - 2];
            }
          } elseif (isset($parts[$timeIndex - 2]) && preg_match('/^[A-Za-z]{3}$/', $parts[$timeIndex - 2]) && isset($parts[$timeIndex - 1]) && preg_match('/^\d{1,2}$/', $parts[$timeIndex - 1])) {
            $month = $parts[$timeIndex - 2];
            $day = $parts[$timeIndex - 1];
          }
        }
        if ($month && $day) {
          $year = date('Y');
          $loginTimestamp = strtotime(sprintf('%s %s %s', $month, $day, $year) . ' ' . $time);
          if ($loginTimestamp !== false && $loginTimestamp > time() + 60) {
            $loginTimestamp = strtotime(sprintf('%s %s %s', $month, $day, $year - 1) . ' ' . $time);
          }
        } else {
          $loginTimestamp = @strtotime($date . ' ' . $time);
        }
      }
      if ($loginTimestamp === false || $loginTimestamp === null) {
        $loginTimestamp = time();
      }
      $nowTimestamp = time();
      $durationSec = $nowTimestamp - $loginTimestamp;
      if ($durationSec < 0)
        $durationSec = 0;
      $hours = floor($durationSec / 3600);
      $minutes = floor(($durationSec % 3600) / 60);
      $seconds = $durationSec % 60;
      if ($hours > 0) {
        $durationStr = sprintf('%dh %dm %ds', $hours, $minutes, $seconds);
      } elseif ($minutes > 0) {
        $durationStr = sprintf('%dm %ds', $minutes, $seconds);
      } else {
        $durationStr = sprintf('%ds', $seconds);
      }
      $sessions[] = sprintf('User: %s | TTY: %s | IP: %s%s%s | Time: %s %s | Duration: %s', $user, $tty, $ip, $ipType, $countryStr, $date, $time, $durationStr);
    } else {
      $sessions[] = $line;
    }
  }
  return $sessions;
}
function getBlockedIPs()
{
  global $blockedIPsFile;
  return json_decode(file_get_contents($blockedIPsFile), true);
}

function getNotes()
{
  global $notesFile;
  $j = @file_get_contents($notesFile);
  $data = json_decode($j, true);
  if (!is_array($data))
    return [];
  return $data;
}

function saveNotes($notes)
{
  global $notesFile;
  return file_put_contents($notesFile, json_encode($notes, JSON_PRETTY_PRINT));
}
function blockIP($ip)
{
  global $blockedIPsFile;
  $blocked = getBlockedIPs();
  if (!in_array($ip, $blocked)) {
    $blocked[] = $ip;
    file_put_contents($blockedIPsFile, json_encode($blocked));
    exec("sudo iptables -A INPUT -s $ip -j DROP 2>/dev/null", $output, $return);
    echo $ip[0] . "" . $output[1] . "";
    return $return === 0;
  }
  return true;
}
function unblockIP($ip)
{
  global $blockedIPsFile;
  $blocked = getBlockedIPs();
  if (($key = array_search($ip, $blocked)) !== false) {
    unset($blocked[$key]);
    file_put_contents($blockedIPsFile, json_encode(array_values($blocked)));
    exec("sudo iptables -D INPUT -s $ip -j DROP 2>/dev/null", $output, $return);
    return $return === 0;
  }
  return true;
}

if (isset($_GET['action'])) {
  header('Content-Type:application/json');
  $now = time();
  $viewerIP = $_SERVER['REMOTE_ADDR'];

  switch ($_GET['action']) {

    case 'health':
      $load = floatval(explode(' ', file_get_contents('/proc/loadavg'))[0]);
      preg_match('/Mem:\s+(\d+)\s+(\d+)/', shell_exec('free -m'), $m);
      $mem = ['total' => $m[1], 'used' => $m[2]];
      $tot = disk_total_space('/');
      $free = disk_free_space('/');
      $disk = ['total' => round($tot / 1024 ** 3, 1), 'used' => round(($tot - $free) / 1024 ** 3, 1)];
      echo json_encode([
        'load' => round($load, 1),
        'mem' => $mem,
        'disk' => $disk,
        'temp' => getTemp(),
        'swap' => getSwap(),
        'uptime' => getUptime(),
        'netThr' => getNetThroughput()
      ]);
      break;

    case 'ping':
      $lines = file_exists($accessLog) ? file($accessLog) : [];
      $byip = [];
      $forbidden = [];
      $lastVisit = [];

      foreach ($lines as $l) {
        if (preg_match('/(\d+\.\d+\.\d+\.\d+).*?\[(.*?)\]/', $l, $m)) {
          $ip = $m[1];
          $ts = strtotime($m[2]);
          if (($now - $ts) <= $timeWindow) {
            $byip[$ip] = ($byip[$ip] ?? 0) + 1;
            if (!isset($lastVisit[$ip]) || $ts > $lastVisit[$ip]) {
              $lastVisit[$ip] = $ts;
            }
          }
        }
        if (preg_match('/(\d+\.\d+\.\d+\.\d+).*?\[(.*?)\].*?"\s403\s/', $l, $m403)) {
          $ip403 = $m403[1];
          $ts403 = strtotime($m403[2]);
          if (($now - $ts403) <= $timeWindow) {
            $forbidden[$ip403] = ($forbidden[$ip403] ?? 0) + 1;
          }
        }
      }
      arsort($byip);
      arsort($forbidden);
      $top = array_slice($byip, 0, 10, true);
      $top403 = $forbidden;
      unset($top[$viewerIP]);
      unset($top403[$viewerIP]);
      $alerts = [];
      foreach ($top as $ip => $c) {
        if ($c > $ddosThreshold) {
          $t = date('Y-m-d H:i:s');
          $alerts[] = "$t $ip ($c reqs)";
          file_put_contents($ddosLog, "$t $ip\n", FILE_APPEND);
        }
      }
      echo json_encode(['top' => $top, 'alerts' => $alerts, 'top403' => $top403, 'lastVisit' => $lastVisit]);
      break;

    case 'traffic':
      $lines = file_exists($accessLog) ? file($accessLog) : [];
      $req = 0;
      $sum = 0;
      $byip = [];
      foreach ($lines as $l) {
        if (
          preg_match(
            '/(\d+\.\d+\.\d+\.\d+).*?\[(.*?)\].*?"\s\d+\s.*?"\s".*?"\s([\d\.]+)$/',
            $l,
            $m
          )
        ) {
          $ip = $m[1];
          $ts = strtotime($m[2]);
          $rt = (float) $m[3];
          if (($now - $ts) <= $timeWindow) {
            $req++;
            $sum += $rt;
            $byip[$ip] = ($byip[$ip] ?? 0) + 1;
          }
        }
      }
      arsort($byip);
      echo json_encode([
        'requests' => $req,
        'avg' => $req ? round($sum / $req, 3) : 0,
        'byip' => $byip
      ]);
      break;
    case 'advanced':
      echo json_encode([
        'sv' => getServices(),
        'pr' => getTopProcs(),
        'lg' => getLogSummary(),
        'al' => getAccessLogSummary(),
        'ssh' => getActiveSSH()
      ]);
      break;
    case 'get_blocked_ips':
      require_once __DIR__ . '/ip_rules_helper.php';
      echo json_encode(['blocked' => getBlockedIPsFromConf()]);
      break;

    case 'get_notes':
      echo json_encode(['notes' => getNotes()]);
      break;

    case 'set_note':
      if (isset($_GET['ip']) && filter_var($_GET['ip'], FILTER_VALIDATE_IP)) {
        $ip = $_GET['ip'];
        $note = isset($_GET['note']) ? $_GET['note'] : null;
        $notes = getNotes();
        $notes[$ip] = $note === null ? null : (string) $note;
        saveNotes($notes);
        echo json_encode(['success' => true]);
      } else {
        echo json_encode(['error' => 'Invalid IP']);
      }
      break;

    case 'delete_note':
      if (isset($_GET['ip']) && filter_var($_GET['ip'], FILTER_VALIDATE_IP)) {
        $ip = $_GET['ip'];
        $notes = getNotes();
        if (array_key_exists($ip, $notes))
          unset($notes[$ip]);
        saveNotes($notes);
        echo json_encode(['success' => true]);
      } else {
        echo json_encode(['error' => 'Invalid IP']);
      }
      break;

    case 'block_ip':
      if (isset($_GET['ip']) && filter_var($_GET['ip'], FILTER_VALIDATE_IP)) {
        require_once __DIR__ . '/ip_rules_helper.php';
        $success = blockIPInConf($_GET['ip']);
        echo json_encode(['success' => $success]);
      } else {
        echo json_encode(['error' => 'Invalid IP address']);
      }
      break;

    case 'unblock_ip':
      if (isset($_GET['ip']) && filter_var($_GET['ip'], FILTER_VALIDATE_IP)) {
        require_once __DIR__ . '/ip_rules_helper.php';
        $success = unblockIPInConf($_GET['ip']);
        echo json_encode(['success' => $success]);
      } else {
        echo json_encode(['error' => 'Invalid IP address']);
      }
      break;

    default:
      echo json_encode(['error' => 'unknown action']);
  }
  exit;
}
?><!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8">
  <title>Server 1 Monitoring Dashboard</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <link rel="shortcut icon"
    href="LOGO.PNG">
  <script src="https://kit.fontawesome.com/a2e0d1f4f0.js" crossorigin="anonymous"></script>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    body {
      background: linear-gradient(135deg, #e3eafc 0%, #f8f9fa 100%);
      font-family: 'Inter', 'Segoe UI', Arial, sans-serif;
      color: #222;
    }

    .modern-card {
      border: none;
      border-radius: 1rem;
      box-shadow: 0 2px 16px rgba(13, 110, 253, 0.08);
      background: #fff;
      transition: box-shadow .2s;
    }

    .note-container .note-edit .note-input {
      width: 100%;
    }

    .note-container .btn-link {
      padding: 0;
      font-size: 0.9rem
    }

    .modern-card:hover {
      box-shadow: 0 4px 24px rgba(13, 110, 253, 0.15);
    }

    .card-icon {
      font-size: 2.5rem;
      opacity: .7;
      color: #158da5ff;
      margin-bottom: .5rem;
    }

    .nav-pills .nav-link {
      border-radius: 2rem;
      font-weight: 500;
      color: #158da5ff;
      background: #e3eafc;
      margin-right: .5rem;
      transition: background .2s, color .2s;
    }

    .nav-pills .nav-link.active {
      background: #158da5ff;
      color: #fff;
      box-shadow: 0 2px 8px rgba(13, 110, 253, 0.10);
    }

    .table {
      border-radius: .75rem;
      overflow: hidden;
      box-shadow: 0 1px 8px rgba(13, 110, 253, 0.07);
      background: #fff;
    }

    .table th {
      background: #e3eafc;
      color: #158da5ff;
      font-weight: 600;
    }

    .table-danger {
      background: #ffe3e3 !important;
      color: #d90429;
    }

    .list-group-item {
      border: none;
      border-radius: .5rem;
      margin-bottom: .25rem;
      background: #f4f7ff;
      color: #222;
    }

    .fs-5 {
      font-size: 1.35rem !important;
      font-weight: 500;
    }

    h1,
    h5,
    h6 {
      font-weight: 700;
      letter-spacing: -.5px;
    }

    pre {
      background: #f4f7ff;
      border-radius: .5rem;
      padding: .75rem 1rem;
      font-size: 1rem;
      color: #444;
      box-shadow: 0 1px 4px rgba(13, 110, 253, 0.04);
    }

    .tab-pane {
      padding-top: 1rem;
    }

    .mb-4 {
      margin-bottom: 2rem !important;
    }

    .mb-3 {
      margin-bottom: 1.5rem !important;
    }

    .gy-3 {
      row-gap: 1.5rem !important;
    }

    .modern-shadow {
      box-shadow: 0 2px 16px rgba(13, 110, 253, 0.08);
    }

    @media (max-width: 768px) {
      .card-icon {
        font-size: 2rem;
      }

      .fs-5 {
        font-size: 1.1rem !important;
      }
    }
  </style>
</head>

<body>
  <div class="container my-4">
    <h1 class="mb-4" style="color: #444;"><i class="fas fa-tachometer-alt"></i> Server 1 Monitoring Dashboard</h1>
    <ul class="nav nav-pills mb-3">
      <li class="nav-item"><button class="nav-link active" data-bs-toggle="pill"
          data-bs-target="#tabHealth">Health</button></li>
      <li class="nav-item"><button class="nav-link" data-bs-toggle="pill" data-bs-target="#tabDDoS">Traffic
          Monitoring</button></li>
      <li class="nav-item"><button class="nav-link" data-bs-toggle="pill" data-bs-target="#tabIP">IP Management</button>
      </li>
      <li class="nav-item"><button class="nav-link" data-bs-toggle="pill" data-bs-target="#tabAdv">Advanced</button>
      </li>
    </ul>

    <div class="tab-content">
      <div class="tab-pane fade show active" id="tabHealth">
        <div class="row gy-3">
          <?php
          $cards = [
            ['icon' => 'microchip', 'label' => 'CPU Load', 'id' => 'cpuLoad', 'unit' => '%'],
            ['icon' => 'memory', 'label' => 'RAM Usage', 'id' => 'ramUsage', 'unit' => ' MB'],
            ['icon' => 'hdd', 'label' => 'Storage', 'id' => 'diskUsage', 'unit' => ' GB'],
            ['icon' => 'swap', 'label' => 'Swap Usage', 'id' => 'swapUsage', 'unit' => ' MB'],
            ['icon' => 'clock', 'label' => 'Uptime', 'id' => 'uptime', 'unit' => ''],
            ['icon' => 'exchange-alt', 'label' => 'Net Thr', 'id' => 'netThr', 'unit' => ' KiB/s'],
            ['icon' => 'thermometer-half', 'label' => 'Temp', 'id' => 'cpuTemp', 'unit' => ' °C']
          ];
          foreach ($cards as $c) {
            echo "
          <div class='col-12 col-sm-6 col-md-4 col-lg-3'>
            <div class='modern-card card text-center py-3 px-2'>
              <div class='card-body'>
                <i class='fas fa-{$c['icon']} card-icon'></i>
                <h6 class='mb-2'>{$c['label']}</h6>
                <p id='{$c['id']}' class='fs-5 mb-0'>–{$c['unit']}</p>
                <div class='loader-bar' id='loader-{$c['id']}' style='height:8px;width:100%;background:#e3eafc;border-radius:4px;overflow:hidden;margin-top:8px;position:relative;'>
                  <div style='height:100%;width:0%;background:#158da5ff;transition:width 0.5s;' id='loader-fill-{$c['id']}'></div>
                  <span id='loader-percent-{$c['id']}' style='position:absolute;right:8px;top:-18px;font-size:0.95em;color:#222;'></span>
                </div>
              </div>
            </div>
          </div>";
          }
          ?>
        </div>
        <div class="mt-4">
          <h5>Live Health Metrics</h5>
          <canvas id="healthChart" height="120"></canvas>
        </div>
      </div>

      <div class="tab-pane fade" id="tabDDoS">
        <div class="d-flex justify-content-between mb-3">
          <h5>Top 10 IPs (last 5 Days)</h5>
          <div>
            <span class="badge bg-dark fs-6">
              Total Unique IPs: <span id="totalUniqueIPs">0</span>
            </span>
          </div>
        </div>

        <canvas id="ddosChart" height="100" class="mb-3"></canvas>

        <table class="table">
          <thead>
            <tr>
              <th>IP</th>
              <th>Count</th>
              <th>Last Visit</th>
              <th>Traffic Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody id="ddosTable">
            <tr>
              <td colspan="5">Loading…</td>
            </tr>
          </tbody>
        </table>

        <h6>Alerts</h6>
        <pre id="ddosAlerts">Loading…</pre>

        <h5 class="mt-4">IPs Visited (403) Forbidden</h5>
        <div class="d-flex justify-content-between mb-2">
          <span>IPs with 403 errors: <span id="total403IPs">0</span></span>
        </div>
        <table class="table">
          <thead>
            <tr>
              <th>IP</th>
              <th>403 Count</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody id="ddos403Table">
            <tr>
              <td colspan="3">Loading…</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div class="tab-pane fade" id="tabTraffic">
        <div class="d-flex justify-content-between mb-3">
          <span><strong id="reqCount">–</strong> reqs / <?php echo $timeWindow ?>s</span>
          <span>Avg resp: <strong id="avgTime">–</strong>s</span>
        </div>
        <canvas id="trafficChart" height="100"></canvas>
        <table class="table mt-3">
          <thead>
            <tr>
              <th>IP</th>
              <th>Count</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody id="trafficTable">
            <tr>
              <td colspan="4">No traffic in last <?php echo $timeWindow ?>s</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div class="tab-pane fade" id="tabIP">
        <div class="row">
          <div class="col-md-6">
            <h5>Block New IP</h5>
            <div class="input-group mb-3">
              <input type="text" id="ipToBlock" class="form-control" placeholder="IP Address">
              <button class="btn btn-danger" type="button" onclick="blockNewIP()">Block</button>
            </div>
          </div>
          <div class="col-md-6">
            <h5>Search blocked IPs</h5>
            <div class="input-group mb-3">
              <input type="text" id="blockedSearch" class="form-control" placeholder="Search IP or note...">
            </div>
          </div>
        </div>

        <h5>Currently Blocked IPs</h5>
        <table class="table">
          <thead>
            <tr>
              <th>IP Address</th>
              <th>Country</th>
              <th>Note</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody id="blockedIPs">
            <tr>
              <td colspan="4">Loading...</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="tab-pane fade" id="tabAdv">
        <h5>Service Status</h5>
        <ul id="svcList" class="list-group mb-3">
          <li class="list-group-item">Loading…</li>
        </ul>
        <h5>Active SSH Sessions</h5>
        <pre id="sshList">Loading…</pre>
        <h5>Top Processes</h5>
        <pre id="procList">Loading…</pre>
        <h5>NGINX Error Log</h5>
        <pre id="logList" class="text-danger">Loading…</pre>
        <h5>NGINX Access Log</h5>
        <pre id="accessList">Loading…</pre>
      </div>

    </div>
  </div>
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <script>
    (async () => {
      const ddosTh = <?php echo $ddosThreshold ?>;
      let ddosChart, trafficChart, healthChart;
      let blockedIPs = [];
      const ddosChartConfig = {
        type: 'bar',
        data: {
          labels: [],
          datasets: [{
            label: 'Requests',
            data: [],
            backgroundColor: [],
            borderColor: [],
            borderWidth: 1
          }]
        },
        options: {
          responsive: true,
          animation: {
            duration: 500,
            easing: 'easeOutQuart'
          },
          plugins: {
            legend: { display: false },
            tooltip: {
              enabled: true,
              callbacks: {
                label: function (context) {
                  return `${context.label}: ${context.parsed.y} requests`;
                }
              }
            }
          },
          scales: {
            x: {
              title: { display: false },
              grid: { display: false }
            },
            y: {
              beginAtZero: true,
              grid: { color: 'rgba(13,110,253,0.07)' }
            }
          }
        }
      };
      const healthData = {
        labels: [],
        cpu: [],
        ram: [],
        disk: [],
        temp: []
      };

      async function ajax(action, params = {}) {
        const urlParams = new URLSearchParams(params);
        const res = await fetch(`?action=${action}&${urlParams}`);
        return res.json();
      }

      async function refreshHealth() {
        const d = await ajax('health');
        const cpuPercent = Math.min(100, Math.round(parseFloat(d.load)));
        const ramPercent = d.mem.total ? Math.round((d.mem.used / d.mem.total) * 100) : 0;
        const diskPercent = d.disk.total ? Math.round((d.disk.used / d.disk.total) * 100) : 0;
        const swapPercent = d.swap.total ? Math.round((d.swap.used / d.swap.total) * 100) : 0;
        document.getElementById('loader-fill-cpuLoad').style.width = cpuPercent + '%';
        document.getElementById('loader-percent-cpuLoad').textContent = cpuPercent + '%';
        document.getElementById('loader-fill-ramUsage').style.width = ramPercent + '%';
        document.getElementById('loader-percent-ramUsage').textContent = ramPercent + '%';
        document.getElementById('loader-fill-diskUsage').style.width = diskPercent + '%';
        document.getElementById('loader-percent-diskUsage').textContent = diskPercent + '%';
        document.getElementById('loader-fill-swapUsage').style.width = swapPercent + '%';
        document.getElementById('loader-percent-swapUsage').textContent = swapPercent + '%';
        document.getElementById('loader-fill-uptime').style.width = '10%';
        document.getElementById('loader-percent-uptime').textContent = '';
        document.getElementById('loader-fill-netThr').style.width = '7%';
        document.getElementById('loader-percent-netThr').textContent = '';
        document.getElementById('loader-fill-cpuTemp').style.width = '30%';
        document.getElementById('loader-percent-cpuTemp').textContent = '';
        document.getElementById('cpuLoad').textContent = d.load + '%';
        document.getElementById('ramUsage').textContent = `${d.mem.used}/${d.mem.total} MB`;
        document.getElementById('diskUsage').textContent = `${d.disk.used}/${d.disk.total} GB`;
        document.getElementById('swapUsage').textContent = `${d.swap.used}/${d.swap.total} MB`;
        document.getElementById('uptime').textContent = d.uptime;
        document.getElementById('netThr').textContent = `${d.netThr.rx}/${d.netThr.tx}`;
        document.getElementById('cpuTemp').textContent = d.temp + ' °C';
        const nowLabel = new Date().toLocaleTimeString();
        if (healthData.labels.length >= 20) {
          healthData.labels.shift();
          healthData.cpu.shift();
          healthData.ram.shift();
          healthData.disk.shift();
          healthData.temp.shift();
        }
        healthData.labels.push(nowLabel);
        healthData.cpu.push(d.load);
        healthData.ram.push(d.mem.used);
        healthData.disk.push(d.disk.used);
        healthData.temp.push(d.temp);
        if (healthChart) healthChart.destroy();
        healthChart = new Chart(
          document.getElementById('healthChart'),
          {
            type: 'line',
            data: {
              labels: healthData.labels,
              datasets: [
                {
                  label: 'CPU Load',
                  data: healthData.cpu,
                  borderColor: '#158da5ff',
                  backgroundColor: 'rgba(13,110,253,0.08)',
                  tension: 0.3,
                  fill: false
                },
                {
                  label: 'RAM Used (MB)',
                  data: healthData.ram,
                  borderColor: '#6610f2',
                  backgroundColor: 'rgba(102,16,242,0.08)',
                  tension: 0.3,
                  fill: false
                },
                {
                  label: 'Disk Used (GB)',
                  data: healthData.disk,
                  borderColor: '#fd7e14',
                  backgroundColor: 'rgba(253,126,20,0.08)',
                  tension: 0.3,
                  fill: false
                },
                {
                  label: 'CPU Temp (°C)',
                  data: healthData.temp,
                  borderColor: '#d90429',
                  backgroundColor: 'rgba(217,4,41,0.08)',
                  tension: 0.3,
                  fill: false
                }
              ]
            },
            options: {
              responsive: true,
              plugins: {
                legend: { position: 'top' }
              },
              scales: {
                x: { display: true, title: { display: false } },
                y: { beginAtZero: true }
              }
            }
          }
        );
      }

      async function refreshBlockedIPs() {
        const [data, notesResp] = await Promise.all([ajax('get_blocked_ips'), ajax('get_notes')]);
        blockedIPs = data.blocked || [];
        const notes = notesResp.notes || {};

        let rows;
        if (blockedIPs.length === 0) {
          rows = '<tr><td colspan="4">No IPs currently blocked</td></tr>';
        } else {
          rows = blockedIPs.map(ip => {
            const note = (notes && Object.prototype.hasOwnProperty.call(notes, ip)) ? notes[ip] : null;
            const noteDisplay = note === null || note === '' ? '<em class="text-muted">No note</em>' : `<span class="note-text">${escapeHtml(note)}</span>`;
            return `
        <tr>
          <td>${ip}</td>
          <td>N/A Not Available Now</td>
          <td>
            <div class="note-container" data-ip="${ip}">
              <div class="note-view">${noteDisplay} <button class="btn btn-sm btn-link" onclick="editNote('${ip}')">Edit</button></div>
              <div class="note-edit" style="display:none;">
                <input class="form-control form-control-sm note-input" value="${note === null ? '' : escapeHtml(note)}" placeholder="Add note (optional)">
                <div class="mt-1">
                  <button class="btn btn-sm btn-primary" onclick="saveNote('${ip}')">Save</button>
                  <button class="btn btn-sm btn-secondary" onclick="cancelEdit('${ip}')">Cancel</button>
                  <button class="btn btn-sm btn-danger" onclick="deleteNote('${ip}')">Delete</button>
                </div>
              </div>
            </div>
          </td>
          <td>
            <button class="btn btn-sm btn-success" style="background-color:green;" onclick="unblockIP('${ip}')">Unblock</button>
          </td>
        </tr>
        `;
          }).join('');
        }
        document.getElementById('blockedIPs').innerHTML = rows;
        const si = document.getElementById('blockedSearch');
        if (si && si.value) filterBlockedRows(si.value);
      }
      function filterBlockedRows(q) {
        q = (q || '').toLowerCase().trim();
        const rows = document.querySelectorAll('#blockedIPs tr');
        rows.forEach(r => {
          const ipCell = r.querySelector('td:nth-child(1)');
          const noteCell = r.querySelector('td:nth-child(3)');
          if (!ipCell) return;
          const ipText = ipCell.textContent.toLowerCase();
          const noteText = noteCell ? noteCell.textContent.toLowerCase() : '';
          if (q === '' || ipText.includes(q) || noteText.includes(q)) {
            r.style.display = '';
          } else {
            r.style.display = 'none';
          }
        });
      }

      function debounce(fn, ms) {
        let t;
        return function (...a) {
          clearTimeout(t);
          t = setTimeout(() => fn.apply(this, a), ms);
        }
      }

      const searchInput = document.getElementById('blockedSearch');
      if (searchInput) {
        searchInput.addEventListener('input', debounce((e) => filterBlockedRows(e.target.value), 150));
      }

      function escapeHtml(s) {
        if (!s) return '';
        return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
      }

      function editNote(ip) {
        const container = document.querySelector(`.note-container[data-ip="${ip}"]`);
        if (!container) return;
        container.querySelector('.note-view').style.display = 'none';
        container.querySelector('.note-edit').style.display = 'block';
      }
      window.editNote = editNote;

      function cancelEdit(ip) {
        const container = document.querySelector(`.note-container[data-ip="${ip}"]`);
        if (!container) return;
        container.querySelector('.note-edit').style.display = 'none';
        container.querySelector('.note-view').style.display = 'block';
      }
      window.cancelEdit = cancelEdit;

      async function saveNote(ip) {
        const container = document.querySelector(`.note-container[data-ip="${ip}"]`);
        if (!container) return;
        const input = container.querySelector('.note-input');
        const noteRaw = input.value || '';
        const note = noteRaw.trim();
        if (note.length === 0) {
          await ajax('delete_note', { ip });
        } else {
          await ajax('set_note', { ip, note });
        }
        await refreshBlockedIPs();
      }
      window.saveNote = saveNote;

      async function deleteNote(ip) {
        await ajax('delete_note', { ip });
        await refreshBlockedIPs();
      }
      window.deleteNote = deleteNote;

      async function unblockIP(ip) {
        await ajax('unblock_ip', { ip });
        await refreshBlockedIPs();
      }
      window.unblockIP = unblockIP;

      async function refreshDDoS() {
        const d = await ajax('ping');
        const totalUniqueIPs = Object.keys(d.top || {}).length;
        const total403IPs = Object.keys(d.top403 || {}).length;
        document.getElementById('totalUniqueIPs').textContent = totalUniqueIPs;
        document.getElementById('total403IPs').textContent = total403IPs;
        let rows;
        if (!d.top || Object.keys(d.top).length === 0) {
          rows = '<tr><td colspan="5">No IPs detected</td></tr>';
        } else {
          rows = Object.entries(d.top).map(([ip, c]) => {
            const isBlocked = blockedIPs.includes(ip);
            const lastVisitTime = d.lastVisit && d.lastVisit[ip] ?
              new Date(d.lastVisit[ip] * 1000).toLocaleString() :
              'N/A';
            return `
        <tr class="${c > ddosTh ? 'table-danger' : ''}">
          <td>
            <a href="https://whatismyipaddress.com/ip/${ip}" target="_blank" rel="noopener">${ip}</a>
          </td>
          <td>${c}</td>
          <td>${lastVisitTime}</td>
          <td>${c > ddosTh ? 'Suspected' : 'Normal'}</td>
          <td>
            ${isBlocked ?
                `<button class="btn btn-sm btn-success" style="background-color:green;" onclick="unblockIP('${ip}')">Unblock</button>` :
                `<button class="btn btn-sm btn-danger" style="background-color:red;" onclick="blockIP('${ip}')">Block</button>`
              }
          </td>
        </tr>
        `;
          }).join('');
        }
        document.getElementById('ddosTable').innerHTML = rows;
        document.getElementById('ddosAlerts').textContent = d.alerts.length ? d.alerts.join("\n") : 'None';
        let rows403;
        if (!d.top403 || Object.keys(d.top403).length === 0) {
          rows403 = '<tr><td colspan="3">No 403 detected</td></tr>';
        } else {
          rows403 = Object.entries(d.top403).map(([ip, c]) => {
            const isBlocked = blockedIPs.includes(ip);
            return `
        <tr>
          <td>
            <a href="https://whatismyipaddress.com/ip/${ip}" target="_blank" rel="noopener">${ip}</a>
          </td>
          <td>${c}</td>
          <td>
            ${isBlocked ?
                `<button class="btn btn-sm btn-success" onclick="unblockIP('${ip}')">Unblock</button>` :
                `<button class="btn btn-sm btn-danger" onclick="blockIP('${ip}')">Block</button>`
              }
          </td>
        </tr>
        `;
          }).join('');
        }
        document.getElementById('ddos403Table').innerHTML = rows403;
        const labels = Object.keys(d.top), data = Object.values(d.top);
        const bgColors = labels.map(ip => d.top[ip] > ddosTh ? 'rgba(255,99,132,0.6)' : 'rgba(54,162,235,0.6)');
        const borderColors = labels.map(ip => d.top[ip] > ddosTh ? 'rgba(255,99,132,1)' : 'rgba(54,162,235,1)');
        ddosChartConfig.data.labels = labels;
        ddosChartConfig.data.datasets[0].data = data;
        ddosChartConfig.data.datasets[0].backgroundColor = bgColors;
        ddosChartConfig.data.datasets[0].borderColor = borderColors;
        if (!ddosChart) {
          ddosChart = new Chart(document.getElementById('ddosChart'), ddosChartConfig);
        } else {
          ddosChart.update();
        }
      }
      async function refreshTraffic() {
        const d = await ajax('traffic');
        document.getElementById('reqCount').textContent = d.requests;
        document.getElementById('avgTime').textContent = d.avg;
        if (!d.byip || !Object.keys(d.byip).length) {
          document.getElementById('trafficTable').innerHTML = `<tr><td colspan="4">No traffic in last <?php echo $timeWindow ?>s</td></tr>`;
          if (trafficChart) trafficChart.destroy();
          return;
        }
        document.getElementById('trafficTable').innerHTML = Object.entries(d.byip).map(([ip, c]) => {
          const isBlocked = blockedIPs.includes(ip);
          return `
      <tr class="${c > ddosTh ? 'table-danger' : ''}">
        <td>${ip}</td><td>${c}</td>
        <td>${c > ddosTh ? '!' : 'O'}</td>
        <td>
          ${isBlocked ?
              `<button class="btn btn-sm btn-success" onclick="unblockIP('${ip}')">Unblock</button>` :
              `<button class="btn btn-sm btn-danger" onclick="blockIP('${ip}')">Block</button>`
            }
        </td>
      </tr>
    `}).join('');
        const labels = Object.keys(d.byip), vals = Object.values(d.byip);
        if (trafficChart) trafficChart.destroy();
        trafficChart = new Chart(
          document.getElementById('trafficChart'),
          {
            type: 'bar',
            data: { labels, datasets: [{ label: 'Reqs/IP', data: vals, backgroundColor: 'rgba(13,110,253,0.6)', borderColor: 'rgba(13,110,253,1)', borderWidth: 1 }] },
            options: { scales: { y: { beginAtZero: true } } }
          }
        );
      }

      async function refreshAdvanced() {
        const a = await ajax('advanced');
        document.getElementById('svcList').innerHTML = Object.entries(a.sv).map(([s, st]) => `<li class="list-group-item">${s}: ${st}</li>`).join('');
        document.getElementById('procList').textContent = a.pr.join("\n");
        document.getElementById('logList').textContent = a.lg.join("");
        document.getElementById('accessList').textContent = a.al.join("");
        document.getElementById('sshList').textContent = a.ssh.length ? a.ssh.join("\n") : 'No active SSH sessions';
      }
      window.blockIP = async function (ip) {
        const result = await ajax('block_ip', { ip });
        if (result.success) {
          alert(`IP ${ip} blocked successfully`);
          refreshBlockedIPs();
          refreshDDoS();
          refreshTraffic();
        } else {
          alert(`Failed to block IP ${ip}`);
        }
      };

      window.unblockIP = async function (ip) {
        const result = await ajax('unblock_ip', { ip });
        if (result.success) {
          alert(`IP ${ip} unblocked successfully`);
          refreshBlockedIPs();
          refreshDDoS();
          refreshTraffic();
        } else {
          alert(`Failed to unblock IP ${ip}`);
        }
      };

      window.blockNewIP = function () {
        const ip = document.getElementById('ipToBlock').value.trim();
        if (!ip) {
          alert('Please enter an IP address');
          return;
        }
        const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
        if (!ipPattern.test(ip)) {
          alert('Please enter a valid IP address');
          return;
        }

        blockIP(ip);
        document.getElementById('ipToBlock').value = '';
      };
      document.addEventListener('DOMContentLoaded', function () {
        if (window.localStorage && localStorage.getItem('scrollY')) {
          var y = parseInt(localStorage.getItem('scrollY'), 10) || 0;
          setTimeout(function () {
            if (y > 0) window.scrollTo(0, y);
            localStorage.removeItem('scrollY');
          }, 100);
        }
      });
      refreshHealth();
      refreshBlockedIPs();
      refreshDDoS();
      refreshTraffic();
      refreshAdvanced();
      window.addEventListener('beforeunload', function () {
        if (window.localStorage) {
          localStorage.setItem('scrollY', window.scrollY);
        }
      });
      setInterval(refreshHealth, 5000);
      setInterval(refreshBlockedIPs, 10000);
      setInterval(refreshDDoS, 5000);
      setInterval(refreshTraffic, 5000);
      setInterval(refreshAdvanced, 5000);
    })();
  </script>
</body>
</html>
