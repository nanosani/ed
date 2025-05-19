<?php
// Prevent direct access to this file
if (!defined('ABSPATH')) {
    exit;
}

$options = get_option('edhsc_settings');
?>

<div id="edhsc" class="email-domain-health-security-checker">
    <div id="form-container">
        <form id="validatorForm">
            <div class="fieldsWrapper">
                <input
                    type="text"
                    id="domainInput"
                    placeholder="<?php echo esc_attr__( 'Enter a domain name e.g., itechtics.com', EDHSC_TEXT_DOMAIN ); ?>"
                    required
                >
                <input
                    type="text"
                    id="dkimSelectorInput"
                    placeholder="<?php echo esc_attr__( 'DKIM selector (optional)', EDHSC_TEXT_DOMAIN ); ?>"
                >
                <?php wp_nonce_field( 'edhsc_form_action', 'edhsc_form_nonce' ); ?>
                <button type="submit" class="submit">
                    <?php echo esc_html__( 'Scan', EDHSC_TEXT_DOMAIN ); ?>
                </button>
            </div>
        </form>
    </div>
    <div class="main-error"></div>

    <div id="results-container">
        <div id="mxRecord" class="record collapsed">
            <span class="record-header">
                <img src="<?php echo esc_url( plugins_url( 'assets/images/settings-gear-svg.svg', __DIR__ ) ); ?>" class="loader" style="display:none;">
                <?php esc_html_e( 'MX', EDHSC_TEXT_DOMAIN ); ?>
            </span>
            <div class="statusContainer">
                <span class="status"></span>
                <span class="details">
                    <img src="<?php echo esc_url( plugins_url( 'assets/images/arrow-down-svg.svg', __DIR__ ) ); ?>" class="handle">
                </span>
            </div>

            <div id="check1" class="checks" style="order:99; margin-top:20px;">
                <div class="list-container">
                    <span class="result-icon">
                        <img src="<?php echo esc_url( plugins_url( 'assets/images/dot.svg', __DIR__ ) ); ?>" class="loader">
                    </span>
                    <div class="conf-check">
                        <?php esc_html_e( 'Domain must have at least two nameservers.', EDHSC_TEXT_DOMAIN ); ?>
                    </div>
                </div>
            </div>

            <div id="check10" class="checks" style="order:99;">
                <div class="list-container">
                    <span class="result-icon">
                        <img src="<?php echo esc_url( plugins_url( 'assets/images/dot.svg', __DIR__ ) ); ?>" class="loader">
                    </span>
                    <div class="conf-check">
                        <?php esc_html_e( 'Every nameserver must reply with exactly the same MX records.', EDHSC_TEXT_DOMAIN ); ?>
                    </div>
                </div>
            </div>
        </div>

        <div id="spfRecord" class="record collapsed">
            <span class="record-header">
                <img src="<?php echo esc_url( plugins_url( 'assets/images/settings-gear-svg.svg', __DIR__ ) ); ?>" class="loader" style="display:none;">
                <?php esc_html_e( 'SPF', EDHSC_TEXT_DOMAIN ); ?>
            </span>
            <div class="statusContainer">
                <span class="status"></span>
                <span class="details">
                    <img src="<?php echo esc_url( plugins_url( 'assets/images/arrow-down-svg.svg', __DIR__ ) ); ?>" class="handle">
                </span>
            </div>

            <div id="check2" class="checks" style="order:99; margin-top:20px;">
                <div class="list-container">
                    <span class="result-icon">
                        <img src="<?php echo esc_url( plugins_url( 'assets/images/dot.svg', __DIR__ ) ); ?>" class="loader">
                    </span>
                    <div class="conf-check">
                        <?php esc_html_e( 'SPF record must be in correct format.', EDHSC_TEXT_DOMAIN ); ?>
                    </div>
                </div>
            </div>

            <div id="check5" class="checks" style="order:99;">
                <div class="list-container">
                    <span class="result-icon">
                        <img src="<?php echo esc_url( plugins_url( 'assets/images/dot.svg', __DIR__ ) ); ?>" class="loader">
                    </span>
                    <div class="conf-check">
                        <?php esc_html_e( 'SPF record should be resolved within 10 DNS queries.', EDHSC_TEXT_DOMAIN ); ?>
                    </div>
                </div>
            </div>

            <div id="check6" class="checks" style="order:99;">
                <div class="list-container">
                    <span class="result-icon">
                        <img src="<?php echo esc_url( plugins_url( 'assets/images/dot.svg', __DIR__ ) ); ?>" class="loader">
                    </span>
                    <div class="conf-check">
                        <?php esc_html_e( "Domain doesn't have duplicate SPF records.", EDHSC_TEXT_DOMAIN ); ?>
                    </div>
                </div>
            </div>
        </div>

        <div id="dmarcRecord" class="record collapsed">
            <span class="record-header">
                <img src="<?php echo esc_url( plugins_url( 'assets/images/settings-gear-svg.svg', __DIR__ ) ); ?>" class="loader" style="display:none;">
                <?php esc_html_e( 'DMARC', EDHSC_TEXT_DOMAIN ); ?>
            </span>
            <div class="statusContainer">
                <span class="status"></span>
                <span class="details">
                    <img src="<?php echo esc_url( plugins_url( 'assets/images/arrow-down-svg.svg', __DIR__ ) ); ?>" class="handle">
                </span>
            </div>

            <div id="check3" class="checks" style="order:99; margin-top:20px;">
                <div class="list-container">
                    <span class="result-icon">
                        <img src="<?php echo esc_url( plugins_url( 'assets/images/dot.svg', __DIR__ ) ); ?>" class="loader">
                    </span>
                    <div class="conf-check">
                        <?php esc_html_e( 'DMARC record must be in correct format.', EDHSC_TEXT_DOMAIN ); ?>
                    </div>
                </div>
            </div>

            <div id="check8" class="checks" style="order:99;">
                <div class="list-container">
                    <span class="result-icon">
                        <img src="<?php echo esc_url( plugins_url( 'assets/images/dot.svg', __DIR__ ) ); ?>" class="loader">
                    </span>
                    <div class="conf-check">
                        <?php esc_html_e( 'Every nameserver must reply with exactly the same TXT DMARC records.', EDHSC_TEXT_DOMAIN ); ?>
                    </div>
                </div>
            </div>

            <div id="check11" class="checks" style="order:99;">
                <div class="list-container">
                    <span class="result-icon">
                        <img src="<?php echo esc_url( plugins_url( 'assets/images/dot.svg', __DIR__ ) ); ?>" class="loader">
                    </span>
                    <div class="conf-check">
                        <?php esc_html_e( "Domain doesn't have duplicate DMARC records.", EDHSC_TEXT_DOMAIN ); ?>
                    </div>
                </div>
            </div>
        </div>

        <div id="dkimRecord" class="record collapsed">
            <span class="record-header">
                <img src="<?php echo esc_url( plugins_url( 'assets/images/settings-gear-svg.svg', __DIR__ ) ); ?>" class="loader" style="display:none;">
                <?php esc_html_e( 'DKIM', EDHSC_TEXT_DOMAIN ); ?>
            </span>
            <div class="statusContainer">
                <span class="status"></span>
                <span class="details">
                    <img src="<?php echo esc_url( plugins_url( 'assets/images/arrow-down-svg.svg', __DIR__ ) ); ?>" class="handle">
                </span>
            </div>

            <div id="check7" class="checks" style="order:99; margin-top:20px;">
                <div class="list-container">
                    <span class="result-icon">
                        <img src="<?php echo esc_url( plugins_url( 'assets/images/dot.svg', __DIR__ ) ); ?>" class="loader">
                    </span>
                    <div class="conf-check">
                        <?php esc_html_e( 'Every nameserver must reply with exactly the same TXT DKIM records.', EDHSC_TEXT_DOMAIN ); ?>
                    </div>
                </div>
            </div>
        </div>

        <div id="mtaStsRecord" class="record collapsed">
            <span class="record-header">
                <img src="<?php echo esc_url( plugins_url( 'assets/images/settings-gear-svg.svg', __DIR__ ) ); ?>" class="loader" style="display:none;">
                <?php esc_html_e( 'MTA‑STS', EDHSC_TEXT_DOMAIN ); ?>
            </span>
            <div class="statusContainer">
                <span class="status"></span>
                <span class="details">
                    <img src="<?php echo esc_url( plugins_url( 'assets/images/arrow-down-svg.svg', __DIR__ ) ); ?>" class="handle">
                </span>
            </div>

            <div id="check4" class="checks" style="order:99; margin-top:20px;">
                <div class="list-container">
                    <span class="result-icon">
                        <img src="<?php echo esc_url( plugins_url( 'assets/images/dot.svg', __DIR__ ) ); ?>" class="loader">
                    </span>
                    <div class="conf-check">
                        <?php esc_html_e( 'MTA‑STS record must be in correct format.', EDHSC_TEXT_DOMAIN ); ?>
                    </div>
                </div>
            </div>

            <div id="check9" class="checks" style="order:99;">
                <div class="list-container">
                    <span class="result-icon">
                        <img src="<?php echo esc_url( plugins_url( 'assets/images/dot.svg', __DIR__ ) ); ?>" class="loader">
                    </span>
                    <div class="conf-check">
                        <?php esc_html_e( 'Every nameserver must reply with exactly the same TXT MTA‑STS records.', EDHSC_TEXT_DOMAIN ); ?>
                    </div>
                </div>
            </div>
        </div>

        <div id="bimiRecord" class="record collapsed">
            <span class="record-header">
                <img src="<?php echo esc_url( plugins_url( 'assets/images/settings-gear-svg.svg', __DIR__ ) ); ?>" class="loader" style="display:none;">
                <?php esc_html_e( 'BIMI', EDHSC_TEXT_DOMAIN ); ?>
            </span>
            <div class="statusContainer">
                <span class="status"></span>
                <span class="details">
                    <img src="<?php echo esc_url( plugins_url('assets/images/arrow-down-svg.svg', __DIR__)); ?>" class="handle">
                </span>
            </div>
        </div>

        <div id="emailBlacklist" class="record blocklistResults collapsed">
            <span class="record-header">
                <img src="<?php echo esc_url( plugins_url( 'assets/images/settings-gear-svg.svg', __DIR__ ) ); ?>" class="loader" style="display:none;">
                <?php esc_html_e( 'Email Blacklist Check', EDHSC_TEXT_DOMAIN ); ?>
            </span>
            <div class="statusContainer">
                <span class="status"></span>
                <span class="details"><img loading="lazy" decoding="async" src="<?php echo esc_url( plugins_url('assets/images/arrow-down-svg.svg', __DIR__)); ?>" class="handle"></span>
            </div>
            <div class="blacklists">
                <div id="barracudacentral-result" class="result-container">
                    <img src="<?php echo esc_url( plugins_url('assets/images/settings-gear-svg.svg', __DIR__)); ?>" class="loader-icon" style="display: none;">
                    <img src="<?php echo esc_url( plugins_url('assets/images/check-circle-svg.svg', __DIR__)); ?>" class="check-icon" style="display: none;">
                    <img src="<?php echo esc_url( plugins_url('assets/images/close-circle-svg.svg', __DIR__)); ?>" class="close-icon" style="display: none;">
                    <span class="blocklist-name">Barracuda</span>
                </div>
                <div id="s5h-result" class="result-container">
                    <img src="<?php echo esc_url( plugins_url('assets/images/settings-gear-svg.svg', __DIR__)); ?>" class="loader-icon" style="display: none;">
                    <img src="<?php echo esc_url( plugins_url('assets/images/check-circle-svg.svg', __DIR__)); ?>" class="check-icon" style="display: none;">
                    <img src="<?php echo esc_url( plugins_url('assets/images/close-circle-svg.svg', __DIR__)); ?>" class="close-icon" style="display: none;">
                    <span class="blocklist-name">all.s5h.net</span>
                </div>
                <div id="spamcop-result" class="result-container">
                    <img src="<?php echo esc_url( plugins_url('assets/images/settings-gear-svg.svg', __DIR__)); ?>" class="loader-icon" style="display: none;">
                    <img src="<?php echo esc_url( plugins_url('assets/images/check-circle-svg.svg', __DIR__)); ?>" class="check-icon" style="display: none;">
                    <img src="<?php echo esc_url( plugins_url('assets/images/close-circle-svg.svg', __DIR__)); ?>" class="close-icon" style="display: none;">
                    <span class="blocklist-name">Spamcop</span>
                </div>
                <div id="psbl-result" class="result-container">
                    <img src="<?php echo esc_url( plugins_url('assets/images/settings-gear-svg.svg', __DIR__)); ?>" class="loader-icon" style="display: none;">
                    <img src="<?php echo esc_url( plugins_url('assets/images/check-circle-svg.svg', __DIR__)); ?>" class="check-icon" style="display: none;">
                    <img src="<?php echo esc_url( plugins_url('assets/images/close-circle-svg.svg', __DIR__)); ?>" class="close-icon" style="display: none;">
                    <span class="blocklist-name">psbl.surriel.com</span>
                </div>
                <div id="sibl-result" class="result-container">
                    <img src="<?php echo esc_url( plugins_url('assets/images/settings-gear-svg.svg', __DIR__)); ?>" class="loader-icon" style="display: none;">
                    <img src="<?php echo esc_url( plugins_url('assets/images/check-circle-svg.svg', __DIR__)); ?>" class="check-icon" style="display: none;">
                    <img src="<?php echo esc_url( plugins_url('assets/images/close-circle-svg.svg', __DIR__)); ?>" class="close-icon" style="display: none;">
                    <span class="blocklist-name">SORBS Spam</span>
                </div>
                <div id="bl-result" class="result-container">
                    <img src="<?php echo esc_url( plugins_url('assets/images/settings-gear-svg.svg', __DIR__)); ?>" class="loader-icon" style="display: none;">
                    <img src="<?php echo esc_url( plugins_url('assets/images/check-circle-svg.svg', __DIR__)); ?>" class="check-icon" style="display: none;">
                    <img src="<?php echo esc_url( plugins_url('assets/images/close-circle-svg.svg', __DIR__)); ?>" class="close-icon" style="display: none;">
                    <span class="blocklist-name">Nordspam</span>
                </div>
            </div>
        </div>

        <div id="ipBlacklist" class="record blocklistResults collapsed">
            <span class="record-header">
                <img src="<?php echo esc_url( plugins_url( 'assets/images/settings-gear-svg.svg', __DIR__ ) ); ?>" class="loader" style="display:none;">
                <?php esc_html_e( 'IP Blacklist Check', EDHSC_TEXT_DOMAIN ); ?>
            </span>
            <div class="statusContainer">
                <span class="status"></span>
                <span class="details"><img loading="lazy" decoding="async" src="<?php echo esc_url( plugins_url('assets/images/arrow-down-svg.svg', __DIR__)); ?>" class="handle"></span>
            </div>
            <div class="blacklists">
                <div id="ip-barracudacentral-result" class="result-container ip-result-container">
                    <img src="<?php echo esc_url( plugins_url('assets/images/settings-gear-svg.svg', __DIR__)); ?>" class="loader-icon" style="display: none;">
                    <img src="<?php echo esc_url( plugins_url('assets/images/check-circle-svg.svg', __DIR__)); ?>" class="check-icon" style="display: none;">
                    <img src="<?php echo esc_url( plugins_url('assets/images/close-circle-svg.svg', __DIR__)); ?>" class="close-icon" style="display: none;">
                    <span class="blocklist-name">Barracuda</span>
                </div>
                <div id="ip-s5h-result" class="result-container ip-result-container">
                    <img src="<?php echo esc_url( plugins_url('assets/images/settings-gear-svg.svg', __DIR__)); ?>" class="loader-icon" style="display: none;">
                    <img src="<?php echo esc_url( plugins_url('assets/images/check-circle-svg.svg', __DIR__)); ?>" class="check-icon" style="display: none;">
                    <img src="<?php echo esc_url( plugins_url('assets/images/close-circle-svg.svg', __DIR__)); ?>" class="close-icon" style="display: none;">
                    <span class="blocklist-name">all.s5h.net</span>
                </div>
                <div id="ip-spamcop-result" class="result-container ip-result-container">
                    <img src="<?php echo esc_url( plugins_url('assets/images/settings-gear-svg.svg', __DIR__)); ?>" class="loader-icon" style="display: none;">
                    <img src="<?php echo esc_url( plugins_url('assets/images/check-circle-svg.svg', __DIR__)); ?>" class="check-icon" style="display: none;">
                    <img src="<?php echo esc_url( plugins_url('assets/images/close-circle-svg.svg', __DIR__)); ?>" class="close-icon" style="display: none;">
                    <span class="blocklist-name">Spamcop</span>
                </div>
                <div id="ip-psbl-result" class="result-container ip-result-container">
                    <img src="<?php echo esc_url( plugins_url('assets/images/settings-gear-svg.svg', __DIR__)); ?>" class="loader-icon" style="display: none;">
                    <img src="<?php echo esc_url( plugins_url('assets/images/check-circle-svg.svg', __DIR__)); ?>" class="check-icon" style="display: none;">
                    <img src="<?php echo esc_url( plugins_url('assets/images/close-circle-svg.svg', __DIR__)); ?>" class="close-icon" style="display: none;">
                    <span class="blocklist-name">psbl.surriel.com</span>
                </div>
                <div id="ip-sibl-result" class="result-container ip-result-container">
                    <img src="<?php echo esc_url( plugins_url('assets/images/settings-gear-svg.svg', __DIR__)); ?>" class="loader-icon" style="display: none;">
                    <img src="<?php echo esc_url( plugins_url('assets/images/check-circle-svg.svg', __DIR__)); ?>" class="check-icon" style="display: none;">
                    <img src="<?php echo esc_url( plugins_url('assets/images/close-circle-svg.svg', __DIR__)); ?>" class="close-icon" style="display: none;">
                    <span class="blocklist-name">SORBS Spam</span>
                </div>
                <div id="ip-bl-result" class="result-container ip-result-container">
                    <img src="<?php echo esc_url( plugins_url('assets/images/settings-gear-svg.svg', __DIR__)); ?>" class="loader-icon" style="display: none;">
                    <img src="<?php echo esc_url( plugins_url('assets/images/check-circle-svg.svg', __DIR__)); ?>" class="check-icon" style="display: none;">
                    <img src="<?php echo esc_url( plugins_url('assets/images/close-circle-svg.svg', __DIR__)); ?>" class="close-icon" style="display: none;">
                    <span class="blocklist-name">Nordspam</span>
                </div>
                <div id="ip-dnsbl-result" class="result-container ip-result-container">
                    <img src="<?php echo esc_url( plugins_url('assets/images/settings-gear-svg.svg', __DIR__)); ?>" class="loader-icon" style="display: none;">
                    <img src="<?php echo esc_url( plugins_url('assets/images/check-circle-svg.svg', __DIR__)); ?>" class="check-icon" style="display: none;">
                    <img src="<?php echo esc_url( plugins_url('assets/images/close-circle-svg.svg', __DIR__)); ?>" class="close-icon" style="display: none;">
                    <span class="blocklist-name">UCEPROTECT</span>
                </div>
            </div>
        </div>
    
    <!-- Conditionally display Summary Container -->
    <?php if (!empty($options['enable_summary_score'])): ?>
    
    <div id="summary-container">
        <div class="summary-items">
            <div id="summaryMxRecord" class="summary-item">
                <img src="<?php echo esc_url( plugins_url('assets/images/check-circle-svg.svg', __DIR__)); ?>" class="summary-icon tick" style="display:none;">
                <img src="<?php echo esc_url( plugins_url('assets/images/warning-svg.svg', __DIR__)); ?>" class="summary-icon warning" style="display:none;">
                <img src="<?php echo esc_url( plugins_url('assets/images/close-circle-svg.svg', __DIR__)); ?>" class="summary-icon cross" style="display:none;">
                <span class="summary-text"></span>
            </div>

            <div id="summarySpfRecord" class="summary-item">
                <img src="<?php echo esc_url( plugins_url('assets/images/check-circle-svg.svg', __DIR__)); ?>" class="summary-icon tick" style="display:none;">
                <img src="<?php echo esc_url( plugins_url('assets/images/warning-svg.svg', __DIR__)); ?>" class="summary-icon warning" style="display:none;">
                <img src="<?php echo esc_url( plugins_url('assets/images/close-circle-svg.svg', __DIR__)); ?>" class="summary-icon cross" style="display:none;">
                <span class="summary-text"></span>
            </div>

            <div id="summaryDmarcRecord" class="summary-item">
                <img src="<?php echo esc_url( plugins_url('assets/images/check-circle-svg.svg', __DIR__)); ?>" class="summary-icon tick" style="display:none;">
                <img src="<?php echo esc_url( plugins_url('assets/images/warning-svg.svg', __DIR__)); ?>" class="summary-icon warning" style="display:none;">
                <img src="<?php echo esc_url( plugins_url('assets/images/close-circle-svg.svg', __DIR__)); ?>" class="summary-icon cross" style="display:none;">
                <span class="summary-text"></span>
            </div>

            <div id="summaryDkimRecord" class="summary-item">
                <img src="<?php echo esc_url( plugins_url('assets/images/check-circle-svg.svg', __DIR__)); ?>" class="summary-icon tick" style="display:none;">
                <img src="<?php echo esc_url( plugins_url('assets/images/warning-svg.svg', __DIR__)); ?>" class="summary-icon warning" style="display:none;">
                <img src="<?php echo esc_url( plugins_url('assets/images/close-circle-svg.svg', __DIR__)); ?>" class="summary-icon cross" style="display:none;">
                <span class="summary-text"></span>
            </div>

            <div id="summaryMtaStsRecord" class="summary-item">
                <img src="<?php echo esc_url( plugins_url('assets/images/check-circle-svg.svg', __DIR__)); ?>" class="summary-icon tick" style="display:none;">
                <img src="<?php echo esc_url( plugins_url('assets/images/warning-svg.svg', __DIR__)); ?>" class="summary-icon warning" style="display:none;">
                <img src="<?php echo esc_url( plugins_url('assets/images/close-circle-svg.svg', __DIR__)); ?>" class="summary-icon cross" style="display:none;">
                <span class="summary-text"></span>
            </div>

            <div id="summaryBimiRecord" class="summary-item">
                <img src="<?php echo esc_url( plugins_url('assets/images/check-circle-svg.svg', __DIR__)); ?>" class="summary-icon tick" style="display:none;">
                <img src="<?php echo esc_url( plugins_url('assets/images/warning-svg.svg', __DIR__)); ?>" class="summary-icon warning" style="display:none;">
                <img src="<?php echo esc_url( plugins_url('assets/images/close-circle-svg.svg', __DIR__)); ?>" class="summary-icon cross" style="display:none;">
                <span class="summary-text"></span>
            </div>

            <div id="summaryEmailBlacklist" class="summary-item">
                <img src="<?php echo esc_url( plugins_url('assets/images/check-circle-svg.svg', __DIR__)); ?>" class="summary-icon tick" style="display:none;">
                <img src="<?php echo esc_url( plugins_url('assets/images/warning-svg.svg', __DIR__)); ?>" class="summary-icon warning" style="display:none;">
                <img src="<?php echo esc_url( plugins_url('assets/images/close-circle-svg.svg', __DIR__)); ?>" class="summary-icon cross" style="display:none;">
                <span class="summary-text"></span>
            </div>

            <div id="summaryIpBlacklist" class="summary-item">
                <img src="<?php echo esc_url( plugins_url('assets/images/check-circle-svg.svg', __DIR__)); ?>" class="summary-icon tick" style="display:none;">
                <img src="<?php echo esc_url( plugins_url('assets/images/warning-svg.svg', __DIR__)); ?>" class="summary-icon warning" style="display:none;">
                <img src="<?php echo esc_url( plugins_url('assets/images/close-circle-svg.svg', __DIR__)); ?>" class="summary-icon cross" style="display:none;">
                <span class="summary-text"></span>
            </div>
        </div>
    </div>
    
    <div id="score-container">
        <p><?php echo esc_html__( 'Email Deliverability Score', EDHSC_TEXT_DOMAIN ); ?></p>
        <div id="overallScore" class="overall-score">
            0/100
        </div>
    </div>
    
    <?php endif; ?>
    
</div>