<?php
function validate_mx_record() {
    check_ajax_referer( 'edhsc_form_nonce', 'nonce' );

    if ( isset( $_POST['domain'] ) ) {
        $domain = sanitize_text_field( wp_unslash( $_POST['domain'] ) );

        if ( ! filter_var( $domain, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME ) ) {
            wp_send_json_error( __( 'Invalid domain provided.', EDHSC_TEXT_DOMAIN ) );
        }

        $mxRecords = dns_get_record( $domain, DNS_MX );
        $ipFound   = false;

        if ( is_array( $mxRecords ) && ! empty( $mxRecords ) ) {
            foreach ( $mxRecords as $mxRecord ) {
                $ip = gethostbyname( $mxRecord['target'] );
                if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
                    $ipFound = true;
                    break;
                }
            }
        }

        if ( $ipFound ) {
            wp_send_json_success( __( 'The domain has a valid MX IP address.', EDHSC_TEXT_DOMAIN ) );
        } else {
            wp_send_json_error( __( 'No valid MX record IP address found.', EDHSC_TEXT_DOMAIN ) );
        }
    } else {
        wp_send_json_error( __( 'Domain not provided.', EDHSC_TEXT_DOMAIN ) );
    }

    wp_die();
}

add_action( 'wp_ajax_validate_mx_record', 'validate_mx_record' );
add_action( 'wp_ajax_nopriv_validate_mx_record', 'validate_mx_record' );


function validate_dns_records()
{
    check_ajax_referer('edhsc_form_nonce', 'nonce');

    if (isset($_POST['domain'])) {
        $domain = sanitize_text_field($_POST['domain']);
        $dkimSelector = isset($_POST['dkimSelector']) && !empty($_POST['dkimSelector']) ? sanitize_text_field($_POST['dkimSelector']) : 'default';
        $response = [
            'mxRecord'   => [
                'available' => false,
                'record'    => __( 'Record not available.', EDHSC_TEXT_DOMAIN ),
                'details'   => [],
            ],
            'spfRecord'  => [
                'available' => false,
                'record'    => __( 'Record not available.', EDHSC_TEXT_DOMAIN ),
                'details'   => [],
            ],
            'dkimRecord' => [
                'available' => false,
                'record'    => __( 'Record not available.', EDHSC_TEXT_DOMAIN ),
                'details'   => [],
            ],
            'dmarcRecord'  => [
                'available' => false,
                'record'    => __( 'Record not available.', EDHSC_TEXT_DOMAIN ),
                'details'   => [],
            ],
            'mtaStsRecord' => [
                'available' => false,
                'record'    => __( 'Record not available.', EDHSC_TEXT_DOMAIN ),
                'details'   => [],
            ],
            'bimiRecord' => [
                'available' => false,
                'record'    => __( 'Record not available.', EDHSC_TEXT_DOMAIN ),
                'details'   => [],
            ],
        ];

        // MX Records
$mxRecords = dns_get_record( $domain, DNS_MX );
if ( is_array( $mxRecords ) && ! empty( $mxRecords ) ) {
    $response['mxRecord']['available'] = true;

    foreach ( $mxRecords as $mxRecord ) {
        $ip = gethostbyname( $mxRecord['target'] );

        if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
            $reverseLookup = gethostbyaddr( $ip );
            $response['mxRecord']['details'][] = array(
                'pref'            => $mxRecord['pri'],
                'hostname'        => $mxRecord['target'],
                'ip'              => $ip,
                'mxReverseLookup' => $reverseLookup,
            );
        } else {
            $response['mxRecord']['details'][] = array(
                'pref'            => $mxRecord['pri'],
                'hostname'        => $mxRecord['target'],
                'ip'              => __( 'Invalid IP', EDHSC_TEXT_DOMAIN ),
                'mxReverseLookup' => __( 'DNS resolution failed.', EDHSC_TEXT_DOMAIN ),
            );
        }
    }
} else {
    $response['mxRecord']['error'] = __( 'Failed to retrieve MX records.', EDHSC_TEXT_DOMAIN );
}


        // Check TXT records for SPF and DMARC
$txtRecords = dns_get_record( $domain, DNS_TXT );
foreach ( $txtRecords as $record ) {
    if ( strpos( $record['txt'], 'v=spf1' ) !== false ) {
        $response['spfRecord']['available'] = true;
        $spfParts    = explode( ' ', $record['txt'] );
        $spfDetails  = array();

        foreach ( $spfParts as $index => $part ) {
            if ( empty( $part ) ) {
                continue;
            }

            $prefix    = '';
            $mechanism = $part;

            if ( 0 !== $index ) {
                if ( strlen( $part ) > 0 && in_array( $part[0], array( '+', '-', '~', '?' ), true ) ) {
                    $prefix    = $part[0];
                    $mechanism = substr( $part, 1 );
                } else {
                    $prefix = '+';
                }
            }

            if ( 'v=spf1' === $part ) {
                $type  = 'v';
                $value = 'spf1';
            } else {
                list( $type, $value ) = array_pad( explode( ':', $mechanism, 2 ), 2, '' );
            }

            $descriptions = array(
                'v'       => __( 'The SPF record version.', EDHSC_TEXT_DOMAIN ),
                'a'       => __( "Match if IP has a DNS 'A' record in given domain.", EDHSC_TEXT_DOMAIN ),
                'mx'      => __( "Match if IP is one of the MX hosts for given domain name.", EDHSC_TEXT_DOMAIN ),
                'include' => __( "The specified domain is searched for an 'allow'.", EDHSC_TEXT_DOMAIN ),
                'ip4'     => __( "Match if IP is in the given range.", EDHSC_TEXT_DOMAIN ),
                'ip6'     => __( "Match if IP is in the given range.", EDHSC_TEXT_DOMAIN ),
                'ptr'     => __( "The hostname or hostnames for the client IP are looked up using PTR queries.", EDHSC_TEXT_DOMAIN ),
                'all'     => __( "Always matches. It goes at the end of your record.", EDHSC_TEXT_DOMAIN ),
            );

            $description = isset( $descriptions[ $type ] ) ? $descriptions[ $type ] : '';

            $spfDetails[] = array(
                'prefix'      => $prefix,
                'type'        => $type,
                'value'       => $value,
                'description' => $description,
            );
        }

        $response['spfRecord']['record']  = $record['txt'];
        $response['spfRecord']['details'] = $spfDetails;
    }
}


        // DMARC record check at _dmarc.<domain>
$dmarcRecords = dns_get_record( "_dmarc.$domain", DNS_TXT );
foreach ( $dmarcRecords as $record ) {
    if ( strpos( $record['txt'], 'v=DMARC1' ) !== false ) {
        $response['dmarcRecord']['available'] = true;
        $dmarcParts   = explode( ';', $record['txt'] );
        $dmarcDetails = array();

        foreach ( $dmarcParts as $part ) {
            $part = trim( $part );
            if ( empty( $part ) ) {
                continue;
            }

            list( $tag, $value ) = array_pad( explode( '=', $part, 2 ), 2, '' );

            $tagsMap = array(
                'v'     => array(
                    'name'        => __( 'Version', EDHSC_TEXT_DOMAIN ),
                    'description' => __( 'Identifies the record retrieved as a DMARC record. It must be the first tag in the list.', EDHSC_TEXT_DOMAIN ),
                ),
                'p'     => array(
                    'name'        => __( 'Policy', EDHSC_TEXT_DOMAIN ),
                    'description' => __( "Policy to apply to email that fails the DMARC test. Valid values can be 'none', 'quarantine', or 'reject'.", EDHSC_TEXT_DOMAIN ),
                ),
                'sp'    => array(
                    'name'        => __( 'Sub-domain Policy', EDHSC_TEXT_DOMAIN ),
                    'description' => __( "Requested Mail Receiver policy for all subdomains. Valid values can be 'none', 'quarantine', or 'reject'.", EDHSC_TEXT_DOMAIN ),
                ),
                'adkim' => array(
                    'name'        => __( 'Alignment Mode DKIM', EDHSC_TEXT_DOMAIN ),
                    'description' => __( "Indicates whether strict or relaxed DKIM Identifier Alignment mode is required by the Domain Owner. Valid values can be 'r' (relaxed) or 's' (strict mode).", EDHSC_TEXT_DOMAIN ),
                ),
                'aspf'  => array(
                    'name'        => __( 'Alignment Mode SPF', EDHSC_TEXT_DOMAIN ),
                    'description' => __( "Indicates whether strict or relaxed SPF Identifier Alignment mode is required by the Domain Owner. Valid values can be 'r' (relaxed) or 's' (strict mode).", EDHSC_TEXT_DOMAIN ),
                ),
                'pct'   => array(
                    'name'        => __( 'Percentage', EDHSC_TEXT_DOMAIN ),
                    'description' => __( "Percentage of messages from the Domain Owner's mail stream to which the DMARC policy is to be applied. Valid value is an integer between 0 to 100.", EDHSC_TEXT_DOMAIN ),
                ),
                'fo'    => array(
                    'name'        => __( 'Forensic Reporting', EDHSC_TEXT_DOMAIN ),
                    'description' => __( "Provides requested options for generation of failure reports. Valid values are any combination of characters '0', '1', 'd', 's' separated by ':'.", EDHSC_TEXT_DOMAIN ),
                ),
                'rf'    => array(
                    'name'        => __( 'Forensic Format', EDHSC_TEXT_DOMAIN ),
                    'description' => __( "Format to be used for message-specific failure reports. Valid values are 'afrf' and 'iodef'.", EDHSC_TEXT_DOMAIN ),
                ),
                'ri'    => array(
                    'name'        => __( 'Reporting Interval', EDHSC_TEXT_DOMAIN ),
                    'description' => __( "Indicates a request to Receivers to generate aggregate reports separated by no more than the requested number of seconds. Valid value is a 32-bit unsigned integer.", EDHSC_TEXT_DOMAIN ),
                ),
            );

            $name        = isset( $tagsMap[ $tag ] ) ? $tagsMap[ $tag ]['name'] : '';
            $description = isset( $tagsMap[ $tag ] ) ? $tagsMap[ $tag ]['description'] : '';

            $dmarcDetails[] = array(
                'tag'         => $tag,
                'value'       => $value,
                'name'        => $name,
                'description' => $description,
            );
        }

        $response['dmarcRecord']['record']  = $record['txt'];
        $response['dmarcRecord']['details'] = $dmarcDetails;
    }
}


        // DKIM record check using "default" selector
        $dkimRecords = dns_get_record("$dkimSelector._domainkey.$domain", DNS_TXT);
        foreach ($dkimRecords as $record) {
            if (strpos($record['txt'], 'v=DKIM1') !== false) {
                $response['dkimRecord']['available'] = true;
                $dkimParts = explode(';', $record['txt']);
                $dkimDetails = [];
                foreach ($dkimParts as $part) {
                    $part = trim($part);
                    if (empty($part)) continue;
                    list($tag, $value) = explode('=', $part, 2);

                    $dkimDetails[] = [
                        'tag' => $tag,
                        'value' => $value
                    ];
                }
                $response['dkimRecord']['record'] = $record['txt'];
                $response['dkimRecord']['details'] = $dkimDetails;
                break;
            }
        }

        // MTA-STS DNS TXT record check
$knownTags = array(
    'v'  => array(
        'name'        => __( 'Version', EDHSC_TEXT_DOMAIN ),
        'description' => __( 'The MTA-STS version. Only STSv1 is currently supported. It must be the first tag in the record.', EDHSC_TEXT_DOMAIN ),
    ),
    'id' => array(
        'name'        => __( 'Identifier', EDHSC_TEXT_DOMAIN ),
        'description' => __( 'A short string ID that allows senders to quickly check if the recipient’s MTA-STS policy has changed.', EDHSC_TEXT_DOMAIN ),
    ),
);

$mtaStsRecords = dns_get_record( "_mta-sts.$domain", DNS_TXT );
foreach ( $mtaStsRecords as $record ) {
    if ( strpos( $record['txt'], 'v=STSv1' ) !== false ) {
        $response['mtaStsRecord']['available'] = true;
        $response['mtaStsRecord']['record']    = $record['txt'];

        $parts = explode( ';', $record['txt'] );
        foreach ( $parts as $part ) {
            $part = trim( $part );
            if ( ! empty( $part ) ) {
                list( $tag, $value ) = array_pad( explode( '=', $part, 2 ), 2, null );
                $tagInfo = isset( $knownTags[ $tag ] ) ? $knownTags[ $tag ] : array(
                    'name'        => '',
                    'description' => '',
                );

                $response['mtaStsRecord']['details'][] = array(
                    'tag'         => $tag,
                    'value'       => $value,
                    'name'        => $tagInfo['name'],
                    'description' => $tagInfo['description'],
                );
            }
        }
        break;
    }
}


        // BIMI DNS TXT record check
$bimiRecords = dns_get_record( "default._bimi.$domain", DNS_TXT );
foreach ( $bimiRecords as $record ) {
    if ( strpos( $record['txt'], 'v=BIMI1' ) !== false ) {
        $response['bimiRecord']['available'] = true;
        $response['bimiRecord']['record']    = $record['txt'];

        $parts = explode( ';', $record['txt'] );
        foreach ( $parts as $part ) {
            $part = trim( $part );
            if ( ! empty( $part ) ) {
                list( $tag, $value ) = array_pad( explode( '=', $part, 2 ), 2, '' );

                $name        = '';
                $description = '';

                if ( 'v' === $tag ) {
                    $name        = __( 'Version', EDHSC_TEXT_DOMAIN );
                    $description = __( 'Identifies the record retrieved as a BIMI record. It must be the first tag in the record.', EDHSC_TEXT_DOMAIN );
                } elseif ( 'l' === $tag ) {
                    $name        = __( 'Location', EDHSC_TEXT_DOMAIN );
                    $description = __( 'Comma separated list of base URLs representing the location of the brand indicator files.', EDHSC_TEXT_DOMAIN );
                }

                $response['bimiRecord']['details'][] = array(
                    'tag'         => $tag,
                    'value'       => $value,
                    'name'        => $name,
                    'description' => $description,
                );
            }
        }

        // Fetch SVG details if location is available
        foreach ( $response['bimiRecord']['details'] as $detail ) {
            if ( 'l' === $detail['tag'] ) {
                $svgUrl = $detail['value'];
                $svgContent = @file_get_contents( $svgUrl );

                if ( false !== $svgContent ) {
                    $svgSize  = strlen( $svgContent ) / 1024; // Size in KB
                    preg_match( '/<title>(.*?)<\/title>/', $svgContent, $matches );
                    $svgTitle = $matches[1] ?? __( 'No title found.', EDHSC_TEXT_DOMAIN );
                } else {
                    $svgSize  = 0;
                    $svgTitle = __( 'Unable to retrieve SVG content.', EDHSC_TEXT_DOMAIN );
                }

                $response['bimiRecord']['svg'] = array(
                    'url'   => $svgUrl,
                    'title' => $svgTitle,
                    'size'  => round( $svgSize, 2 ),
                );
                break;
            }
        }

        break;
    }
}


        echo json_encode($response);
    }
    wp_die();
}

add_action('wp_ajax_validate_dns_records', 'validate_dns_records');
add_action('wp_ajax_nopriv_validate_dns_records', 'validate_dns_records');

// -------------------- DOMAIN AND IP BLACKLISTS CHECKS --------------------- //
function check_blacklist() {
    check_ajax_referer( 'edhsc_form_nonce', 'nonce' );

    $input    = isset( $_POST['input'] ) ? sanitize_text_field( wp_unslash( $_POST['input'] ) ) : '';
    $isDomain = filter_var( $input, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME );
    $isIP     = filter_var( $input, FILTER_VALIDATE_IP );

    if ( ! $isDomain && ! $isIP ) {
        wp_send_json_error( __( 'The domain or IP address is not valid.', EDHSC_TEXT_DOMAIN ) );
    }

    $ip = $input;
    if ( $isDomain ) {
        $ip = gethostbyname( $input );
        if ( $ip === $input ) {
            wp_send_json_error( __( 'The domain could not be resolved to an IP address.', EDHSC_TEXT_DOMAIN ) );
        }
    }

    $blockLists = array(
        'bl.spamcop.net',
        'dob.sibl.support-intelligence.net',
        'b.barracudacentral.org',
        'all.s5h.net',
        'psbl.surriel.com',
        'bl.nordspam.com',
        'dnsbl-1.uceprotect.net',
        // Add more block lists here
    );

    $results = array();

    foreach ( $blockLists as $list ) {
        $query = join( '.', array_reverse( explode( '.', $ip ) ) ) . '.' . $list;
        $results[ $list ] = checkdnsrr( $query, 'A' );
    }

    // Simplify the result for this example; customize as needed
    $simplifiedResults = array(
        'spamcop'             => $results['bl.spamcop.net'],
        'sibl'                => $results['dob.sibl.support-intelligence.net'],
        'barracudacentral'    => $results['b.barracudacentral.org'],
        's5h'                 => $results['all.s5h.net'],
        'psbl'                => $results['psbl.surriel.com'],
        'bl'                  => $results['bl.nordspam.com'],
        'ip-spamcop'          => $results['bl.spamcop.net'],
        'ip-sibl'             => $results['dob.sibl.support-intelligence.net'],
        'ip-barracudacentral' => $results['b.barracudacentral.org'],
        'ip-s5h'              => $results['all.s5h.net'],
        'ip-psbl'             => $results['psbl.surriel.com'],
        'ip-bl'               => $results['bl.nordspam.com'],
        'ip-dnsbl'            => $results['dnsbl-1.uceprotect.net'],
    );

    wp_send_json_success( $simplifiedResults );
}

add_action( 'wp_ajax_check_blacklist', 'check_blacklist' );
add_action( 'wp_ajax_nopriv_check_blacklist', 'check_blacklist' );


function handle_dns_check()
{
    check_ajax_referer('edhsc_form_nonce', 'nonce');

    $domain = sanitize_text_field($_POST['domain']);
    $dkimSelector = isset($_POST['dkimSelector']) && !empty($_POST['dkimSelector']) ? sanitize_text_field($_POST['dkimSelector']) : 'default';
    $check = intval($_POST['check']);
    $response = ['passed' => false];

    if ($check === 1) {
        $records = dns_get_record($domain, DNS_NS);
        $response['passed'] = count($records) >= 2;
    } else if ($check === 2) {
        $records = dns_get_record($domain, DNS_TXT);
        $spfPattern = '/^v=spf1( (?:\+|-|~|\?)?(a|mx|ptr|ip4:[0-9]{1,3}(\.[0-9]{1,3}){3}(\/[0-9]{1,2})?|ip6:[a-fA-F0-9:]+(\/[0-9]{1,3})?|include:[^\s]+|exists:[^\s]+|redirect=[^\s]+|exp=[^\s]+|all))*\s*(~|-|)?all|redirect=[^\s]+\s*$/i';
        $response['passed'] = false;
        foreach ($records as $record) {
            if (preg_match($spfPattern, $record['txt'])) {
                $response['passed'] = true;
                break;
            }
        }
    } else if ($check === 3) {
        $dmarcRecords = dns_get_record('_dmarc.' . $domain, DNS_TXT);
        $dmarcRecordFound = false;
        $response['passed'] = false;
        foreach ($dmarcRecords as $record) {
            $txtRecord = $record['txt'];
            if (strpos($txtRecord, 'v=DMARC1;') !== false) {
                $dmarcRecordFound = true;
                // Split the DMARC record into parts and validate each part
                $parts = explode(';', $txtRecord);
                $valid = true;
                foreach ($parts as $part) {
                    $part = trim($part);
                    if (empty($part)) continue;

                    if (!preg_match('/^(v=DMARC1|p=(none|quarantine|reject)|sp=(none|quarantine|reject)|adkim=(r|s)|aspf=(r|s)|pct=\d{1,3}|fo=(0|1|d|s)|rf=(afrf|iodef)|ri=\d+|rua=mailto:[^;]+(,\s*mailto:[^;]+)*|ruf=mailto:[^;]+(,\s*mailto:[^;]+)*)$/', $part)) {
                        $valid = false;
                        break;
                    }
                }

                if ($valid) {
                    $response['passed'] = true;
                    break;
                }
            }
        }
    } else if ($check === 4) {
        $mtsStsRecords = dns_get_record('_mta-sts.' . $domain, DNS_TXT);
        $response['passed'] = false;
        foreach ($mtsStsRecords as $record) {
            $txtRecord = $record['txt'];
            $pattern = '/^v=STSv1;\s+id=[a-zA-Z0-9]+;?$/';
            if (preg_match($pattern, $txtRecord)) {
                $response['passed'] = true;
                break;
            }
        }
    } else if ($check === 5) {
        $lookupCount = 0;
        $checkedDomains = [];
        fetch_and_count_spf_lookups($domain, $lookupCount, $checkedDomains);
        $response['passed'] = $lookupCount <= 10;
    } else if ($check === 6) {
        $records = dns_get_record($domain, DNS_TXT);
        $spfRecords = [];
        foreach ($records as $record) {
            if (strpos($record['txt'], 'v=spf1') !== false) {
                $spfRecords[] = $record['txt'];
            }
        }
        $response['passed'] = count($spfRecords) <= 1;
    } else if ($check === 7) {
    $nameServers = dns_get_record($domain, DNS_NS);
    $dkimRecords = [];

    foreach ($nameServers as $ns) {
        $recordType = 'TXT';
        $dnsServer = $ns['target'];
        // Build secure command using escapeshellarg() for each dynamic input
        $command = "nslookup -type=" . escapeshellarg($recordType)
            . " " . escapeshellarg("{$dkimSelector}._domainkey.$domain")
            . " " . escapeshellarg($dnsServer);
        $output = shell_exec($command);

        if (!empty($output)) {
            preg_match_all('/text\s*=\s*"(.*?)"/', $output, $matches);
            if (!empty($matches[1])) {
                $dkimRecords[$dnsServer] = join('', $matches[1]);
            } else {
                $dkimRecords[$dnsServer] = __( 'No DKIM record found.', EDHSC_TEXT_DOMAIN );
            }
        } else {
            $dkimRecords[$dnsServer] = __( 'No DKIM record found.', EDHSC_TEXT_DOMAIN );
        }
    }

    // Get the unique responses
    $uniqueRecords = array_unique($dkimRecords);
    $uniqueValue = reset($uniqueRecords);

    // The check now passes only if:
    // a) All nameservers returned the same value,
    // b) That value is not the failure indicator,
    // c) And it contains 'v=DKIM1' (the marker for a valid DKIM record)
    if ( 1 === count( $uniqueRecords ) && $uniqueValue !== __( 'No DKIM record found.', EDHSC_TEXT_DOMAIN ) && strpos( $uniqueValue, 'v=DKIM1' ) !== false ) {
        $response['passed'] = true;
    } else {
        $response['passed'] = false;
    }
}

 else if ($check === 8) {
        $nameServers = dns_get_record($domain, DNS_NS);
        $dmarcRecords = [];
        foreach ($nameServers as $ns) {
            $recordType = 'TXT';
            $dnsServer = $ns['target'];
            $command = "nslookup -type=" . escapeshellarg($recordType)
                . " " . escapeshellarg("_dmarc.$domain")
                . " " . escapeshellarg($dnsServer);
            $output = shell_exec($command);

            if (!empty($output)) {
                preg_match_all('/text = "(.*?)"/', $output, $matches);
                if (!empty($matches[1])) {
                    $dmarcRecords[] = join('', $matches[1]);
                }
            }
        }
        if (count(array_unique($dmarcRecords)) === 1 && !empty($dmarcRecords)) {
            $response['passed'] = true;
        }
    } else if ($check === 9) {
    $nameServers = dns_get_record($domain, DNS_NS);
    $mtaStsRecords = [];

    foreach ($nameServers as $ns) {
        $recordType = 'TXT';
        $dnsServer = $ns['target'];
        // Build secure command using escapeshellarg() for each dynamic input
        $command = "nslookup -type=" . escapeshellarg($recordType)
            . " " . escapeshellarg("_mta-sts.$domain")
            . " " . escapeshellarg($dnsServer);
        $output = shell_exec($command);

        if (!empty($output)) {
            preg_match_all('/text\s*=\s*"(.*?)"/', $output, $matches);
            if (!empty($matches[1])) {
                $mtaStsRecords[$dnsServer] = join('', $matches[1]);
            } else {
                $mtaStsRecords[$dnsServer] = __( 'No MTA-STS record found.', EDHSC_TEXT_DOMAIN );
            }
        } else {
            $mtaStsRecords[$dnsServer] = __( 'No MTA-STS record found.', EDHSC_TEXT_DOMAIN );
        }
    }

    // Determine if all nameservers are returning a valid, identical record.
    $uniqueRecords = array_unique($mtaStsRecords);

    // The check passes only if there is one unique record and that record is not the failure message.
    if (count($uniqueRecords) === 1 && reset($uniqueRecords) !== __( 'No MTA-STS record found.', EDHSC_TEXT_DOMAIN ) ) {
        $response['passed'] = true;
    } else {
        $response['passed'] = false;
    }
}
 else if ($check === 10) {
        $nameServers = dns_get_record($domain, DNS_NS);
        $mxRecordsSets = [];
        foreach ($nameServers as $ns) {
            $dnsServer = $ns['target'];
            $command = "nslookup -type=" . escapeshellarg("MX")
                . " " . escapeshellarg($domain)
                . " " . escapeshellarg($dnsServer);
            $output = shell_exec($command);

            if (!empty($output)) {
                preg_match_all('/mail exchanger = (\S+)/', $output, $matches);
                if (!empty($matches[1])) {
                    sort($matches[1]);
                    $mxRecordsSets[] = join(',', $matches[1]);
                }
            }
        }
        if (count(array_unique($mxRecordsSets)) === 1 && !empty($mxRecordsSets)) {
            $response['passed'] = true;
        }
    } else if ($check === 11) {
        $dmarcRecords = dns_get_record('_dmarc.' . $domain, DNS_TXT);
        $dmarcRecordTexts = [];
        foreach ($dmarcRecords as $record) {
            if (strpos($record['txt'], 'v=DMARC1') !== false) {
                $dmarcRecordTexts[] = $record['txt'];
            }
        }
        $response['passed'] = count($dmarcRecordTexts) <= 1;
    }

    echo json_encode($response);
    wp_die();
}

add_action('wp_ajax_dns_check', 'handle_dns_check');
add_action('wp_ajax_nopriv_dns_check', 'handle_dns_check');


// -------------------- HELPER FUNCTION FOR CHECK NO. 6 --------------------- //
function get_domain_creation_date($domain)
{
    $whois = shell_exec("whois " . escapeshellarg($domain));
    $creationDate = null;

    $patterns = [
        '/Creation Date:\s*(.*)/i',
        '/created:\s*(.*)/i',
        '/Registered on:\s*(.*)/i',
        '/Domain Registration Date:\s*(.*)/i',
        '/Domain Create Date:\s*(.*)/i',
        '/Record created on (.*)/i'
    ];

    foreach ($patterns as $pattern) {
        if (preg_match($pattern, $whois, $matches)) {
            $creationDate = trim($matches[1]);
            break;
        }
    }

    return $creationDate;
}



// -------------------- HELPER FUNCTION FOR CHECK NO. 5 --------------------- //
function fetch_and_count_spf_lookups($domain, &$lookupCount = 0, &$checkedDomains = [])
{
    if (in_array($domain, $checkedDomains)) {
        return $lookupCount;
    }
    $checkedDomains[] = $domain;

    $records = dns_get_record($domain, DNS_TXT);
    foreach ($records as $record) {
        if (strpos($record['txt'], 'v=spf1') === 0) {
            $parts = explode(' ', $record['txt']);
            foreach ($parts as $part) {
                if (preg_match('/^(include|a|mx|ptr|exists):/', $part)) {
                    $lookupCount++;
                    if ($lookupCount > 10) {
                        return $lookupCount;
                    }
                }
                if (strpos($part, 'include:') === 0) {
                    $includeDomain = substr($part, 8);
                    fetch_and_count_spf_lookups($includeDomain, $lookupCount, $checkedDomains);
                    if ($lookupCount > 10) {
                        return $lookupCount;
                    }
                }
            }
        }
    }
    return $lookupCount;
}

// -------------------- Check Blacklists functionality --------------------- //

// Check if the summary container functionality should be processed
if (!empty($options['enable_summary_score'])) {
// Function to fetch Blacklist Check
function get_blacklist_check($domain)
{
    $blacklists = [
        'spamcop' => 'bl.spamcop.net',
        'barracuda' => 'b.barracudacentral.org',
        'sibl' => 'dob.sibl.support-intelligence.net',
        's5h' => 'all.s5h.net',
        'nordspam' => 'bl.nordspam.com'
    ];

    $results = [];

    foreach ($blacklists as $key => $blacklist) {
        $lookup = $domain . '.' . $blacklist;
        $results[$key] = checkdnsrr($lookup, 'A');
    }

    return $results;
}

// AJAX action for Blacklist Check
add_action('wp_ajax_fetch_blacklist_check', 'fetch_blacklist_check');
add_action('wp_ajax_nopriv_fetch_blacklist_check', 'fetch_blacklist_check');

function fetch_blacklist_check()
{
    if ( ! isset( $_GET['domain'] ) ) {
        wp_send_json_error( array(
            'message' => __( 'Domain is required.', EDHSC_TEXT_DOMAIN ),
        ) );
    }

    $domain = sanitize_text_field($_GET['domain']);
    $blacklist_results = get_blacklist_check($domain);

    if ($blacklist_results) {
        wp_send_json_success($blacklist_results);
    } else  {
        wp_send_json_error( array(
            'message' => __( 'Unable to fetch blacklist check results.', EDHSC_TEXT_DOMAIN ),
        ) );
    }
}
}