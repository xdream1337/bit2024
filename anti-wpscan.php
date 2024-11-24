<?php
/*
Plugin Name: Anti-WPScan
Version: 1.0
Author: Jakub Taraba
*/

if (!defined('ABSPATH')) {
    exit; // Zabraňuje priamemu prístupu k súboru
}

// 1. Skrytie verzie WordPressu
remove_action('wp_head', 'wp_generator');
add_filter('the_generator', '__return_empty_string');

// 2. Ochrana pred enumeráciou používateľov cez REST API
add_filter('rest_endpoints', 'awss_remove_users_endpoint');
function awss_remove_users_endpoint($endpoints) {
    if (isset($endpoints['/wp/v2/users'])) {
        unset($endpoints['/wp/v2/users']);
    }
    if (isset($endpoints['/wp/v2/users/(?P<id>[\d]+)'])) {
        unset($endpoints['/wp/v2/users/(?P<id>[\d]+)']);
    }
    return $endpoints;
}

// 3. Zamedzenie prístupu k archívom autorov
add_action('template_redirect', 'awss_block_author_scans');
function awss_block_author_scans() {
    if (is_author()) {
        wp_redirect(home_url());
        exit;
    }
}

// 4. Blokovanie podozrivých User-Agentov
add_action('init', 'awss_block_suspicious_user_agents');
function awss_block_suspicious_user_agents() {
    if (!empty($_SERVER['HTTP_USER_AGENT'])) {
        $blocked_agents = array('WPScan', 'wpscan', 'sqlmap', 'nikto', 'fimap', 'grabber', 'whatweb', 'OpenVAS', 'w3af', 'Arachni', 'nessus', 'Nmap');
        foreach ($blocked_agents as $agent) {
            if (stripos($_SERVER['HTTP_USER_AGENT'], $agent) !== false) {
                header('HTTP/1.1 403 Forbidden');
                exit;
            }
        }
    }
}

// 5. Blokovanie prístupu k citlivým súborom
add_action('template_redirect', 'awss_block_sensitive_files');
function awss_block_sensitive_files() {
    $requested_file = basename($_SERVER['REQUEST_URI']);
    $blocked_files = array('readme.html', 'license.txt', 'wp-config.php', '.htaccess', '.env');
    if (in_array($requested_file, $blocked_files)) {
        header('HTTP/1.1 403 Forbidden');
        exit;
    }
}

// 6. Zakázanie XML-RPC
add_filter('xmlrpc_enabled', '__return_false');

// 7. Blokovanie podozrivých query stringov
add_action('init', 'awss_block_suspicious_queries');
function awss_block_suspicious_queries() {
    $request_uri = $_SERVER['REQUEST_URI'];
    $suspicious_patterns = array(
        '/\.\./', 
        '/UNION.*SELECT/i', 
        '/base64_/i', 
        '/\(null\)/i', 
        '/cmd=/i', 
        '/eval\(/i', 
        '/CONCAT/i', 
        '/(?:\/\*|\*\/|--)/'
    );

    foreach ($suspicious_patterns as $pattern) {
        if (preg_match($pattern, $request_uri)) {
            header('HTTP/1.1 403 Forbidden');
            exit;
        }
    }
}

// 8. Ochrana cez tokenizáciu požiadaviek
add_action('init', 'awss_generate_request_token');
function awss_generate_request_token()
{
    if (!is_user_logged_in()) {
        if (!isset($_COOKIE['awss_request_token'])) {
            $token = bin2hex(random_bytes(16));
            setcookie('awss_request_token', $token, time() + 3600, COOKIEPATH, COOKIE_DOMAIN);
        }
    }
}

add_action('template_redirect', 'awss_verify_request_token');
function awss_verify_request_token()
{
    $protected_paths = array('/wp-admin/', '/wp-login.php');

    foreach ($protected_paths as $path) {
        if (strpos($_SERVER['REQUEST_URI'], $path) !== false) {
            $token = isset($_COOKIE['awss_request_token']) ? $_COOKIE['awss_request_token'] : '';
            if (empty($token)) {
                header('HTTP/1.1 403 Forbidden');
                exit;
            }
        }
    }
}

// 9. Detekcia charakteristických vzorcov požiadaviek
add_action('init', 'awss_detect_scan_patterns');
function awss_detect_scan_patterns()
{
    $request_uri = $_SERVER['REQUEST_URI'];
    $scan_patterns = array(
        '/wp-admin\/admin-ajax.php\?action=revslider_show_image&img=/',
        '/wp-content\/themes\/.*\/(download|setup)\.php/', 
        '/\.env/', 
        '/composer\.json/', 
        '/\/phpinfo\.php/', 
        '/\.(bak|old|save|swp)$/', 
    );

    foreach ($scan_patterns as $pattern) {
        if (preg_match($pattern, $request_uri)) {
            awss_block_request('Detegovaný charakteristický vzorec požiadavky.');
        }
    }
}



?>

