<?php
/*
Plugin Name:  Email Domain Health Checker
Plugin URI:   https://www.itechtics.com
Description:  The Ultimate Email Domain Health Checker Plugin for WordPress.
Version:      1.0.0
Author:       Itechtics Team
Author URI:   https://www.itechtics.com
License:      GPL2
License URI:  https://www.gnu.org/licenses/gpl-2.0.html
*/

// Prevent direct access to the file
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

// Text domain
define( 'EDHSC_TEXT_DOMAIN', 'email-domain-health-checker' );

/**
 * Load plugin textdomain for translations.
 */
add_action( 'plugins_loaded', 'edhsc_load_textdomain' );
function edhsc_load_textdomain() {
    load_plugin_textdomain(
        EDHSC_TEXT_DOMAIN,
        false,
        dirname( plugin_basename( __FILE__ ) ) . '/languages'
    );
}

/**
 * Enqueue front‑end assets and localize strings.
 */
function edhsc_enqueue_assets() {
    
    // Safely enqueue script and style
    wp_enqueue_script('edhsc-script', esc_url(plugin_dir_url(__FILE__) . 'assets/js/main.js'));
    wp_enqueue_style('edhsc-style', esc_url(plugin_dir_url(__FILE__) . 'assets/css/style.css'));

    // Localize AJAX, nonces, images, settings, and user‑facing strings
    wp_localize_script(
        'edhsc-script',
        'edhscData',
        array(
            'ajaxurl'  => admin_url( 'admin-ajax.php' ),
            'nonce'    => wp_create_nonce( 'edhsc_form_nonce' ),
            'images'   => array(
                'loader' => plugins_url( 'assets/images/settings-gear-svg.svg', __FILE__ ),
                'tick'   => plugins_url( 'assets/images/check-circle-svg.svg', __FILE__ ),
                'warning'   => plugins_url( 'assets/images/warning-svg.svg', __FILE__ ),
                'cross'  => plugins_url( 'assets/images/close-circle-svg.svg', __FILE__ ),
            ),
            'settings' => get_option( 'edhsc_settings' ),
            'strings' => array(
                'checking'                  => __( 'Checking…', EDHSC_TEXT_DOMAIN ),
                'noResults'                 => __( 'No domains found.', EDHSC_TEXT_DOMAIN ),
                'errorOccurred'             => __( 'An error occurred.', EDHSC_TEXT_DOMAIN ),
                'invalidFormat'             => __( 'Try entering like this: example.com', EDHSC_TEXT_DOMAIN ),
                'mxError'                   => __( 'The entered domain doesn\'t have a valid MX IP address.', EDHSC_TEXT_DOMAIN ),
                'mxFetchError'              => __( 'Error occurred while checking MX record IP address.', EDHSC_TEXT_DOMAIN ),
                'noRecord'                  => __( 'Record not available.', EDHSC_TEXT_DOMAIN ),

                // Table headers
                'thPref'                    => __( 'Pref', EDHSC_TEXT_DOMAIN ),
                'thHostname'                => __( 'Hostname', EDHSC_TEXT_DOMAIN ),
                'thIpAddress'               => __( 'IP Address', EDHSC_TEXT_DOMAIN ),
                'thMxReverseLookup'         => __( 'MX Reverse Lookup', EDHSC_TEXT_DOMAIN ),
                'thQualifier'               => __( 'Qualifier', EDHSC_TEXT_DOMAIN ),
                'thMechanism'               => __( 'Mechanism', EDHSC_TEXT_DOMAIN ),
                'thValue'                   => __( 'Value', EDHSC_TEXT_DOMAIN ),
                'thDescription'             => __( 'Description', EDHSC_TEXT_DOMAIN ),
                'thTag'                     => __( 'Tag', EDHSC_TEXT_DOMAIN ),
                'thName'                    => __( 'Name', EDHSC_TEXT_DOMAIN ),

                // DKIM tag names
                'dkimVersion'               => __( 'Version', EDHSC_TEXT_DOMAIN ),
                'dkimKeyType'               => __( 'Key type', EDHSC_TEXT_DOMAIN ),
                'dkimPublicKey'             => __( 'Public key', EDHSC_TEXT_DOMAIN ),

                // Status labels
                'statusGood'                => __( 'Good', EDHSC_TEXT_DOMAIN ),
                'statusWarning'             => __( 'Warning', EDHSC_TEXT_DOMAIN ),
                'statusError'               => __( 'Error', EDHSC_TEXT_DOMAIN ),

                // Summary messages
                'summarySetupOk'            => __( 'Great, your %s record is properly set up!', EDHSC_TEXT_DOMAIN ),
                'summaryNeedsAttention'     => __( 'Your %s record is set up but needs attention!', EDHSC_TEXT_DOMAIN ),
                'summaryNeedsSetup'         => __( 'Your %s record needs to be set up!', EDHSC_TEXT_DOMAIN ),

                // Blacklist summaries
                'summaryBlacklistClear'     => __( 'Great, your domain is not blacklisted!', EDHSC_TEXT_DOMAIN ),
                'summaryBlacklistPartial'   => __( 'Attention, your domain is partially blacklisted!', EDHSC_TEXT_DOMAIN ),
                'summaryBlacklistFailed'    => __( 'Attention, your domain is blacklisted!', EDHSC_TEXT_DOMAIN ),

                // IP Blacklist summaries
                'summaryIPBlacklistClear'   => __( 'Great, your IP is not blacklisted!', EDHSC_TEXT_DOMAIN ),
                'summaryIPBlacklistPartial' => __( 'Attention, your IP is partially blacklisted!', EDHSC_TEXT_DOMAIN ),
                'summaryIPBlacklistFailed'  => __( 'Attention, your IP is blacklisted!', EDHSC_TEXT_DOMAIN ),
            ),
        )
    );
}
add_action( 'wp_enqueue_scripts', 'edhsc_enqueue_assets' );

/**
 * Shortcode handler.
 */
function edhsc_shortcode() {
    ob_start();
    include plugin_dir_path( __FILE__ ) . 'templates/checker-form.php';
    return ob_get_clean();
}
add_shortcode( 'edhsc', 'edhsc_shortcode' );

// Include core functionality
include_once plugin_dir_path( __FILE__ ) . 'functionality.php';

/**
 * Allow SVG uploads.
 */
function edhsc_add_svg_mime( $mimes ) {
    $mimes['svg'] = 'image/svg+xml';
    return $mimes;
}
add_filter( 'upload_mimes', 'edhsc_add_svg_mime' );

/**
 * Fix SVG file type checks.
 */
function edhsc_fix_svg_filetype( $data, $file, $filename, $mimes ) {
    $ext = isset( $data['ext'] ) ? $data['ext'] : '';
    if ( 'svg' === $ext ) {
        $data['type'] = 'image/svg+xml';
        $data['ext']  = 'svg';
    }
    return $data;
}
add_filter( 'wp_check_filetype_and_ext', 'edhsc_fix_svg_filetype', 10, 4 );

/**
 * Add “Settings” link on Plugins page.
 */
function edhsc_add_settings_link( $links ) {
    $settings_link = sprintf(
        '<a href="%1$s">%2$s</a>',
        esc_url( admin_url( 'options-general.php?page=edhsc-settings' ) ),
        esc_html__( 'Settings', EDHSC_TEXT_DOMAIN )
    );
    array_push( $links, $settings_link );
    return $links;
}
add_filter( 'plugin_action_links_' . plugin_basename( __FILE__ ), 'edhsc_add_settings_link' );

/**
 * Register admin settings page.
 */
function edhsc_register_settings_page() {
    add_options_page(
        __( 'Email Domain Health Checker Settings', EDHSC_TEXT_DOMAIN ),
        __( 'Email Domain Health Checker', EDHSC_TEXT_DOMAIN ),
        'manage_options',
        'edhsc-settings',
        'edhsc_render_settings_page'
    );
}
add_action( 'admin_menu', 'edhsc_register_settings_page' );

/**
 * Render settings page.
 */
function edhsc_render_settings_page() {
    ?>
    <div class="wrap">
        <h1><?php esc_html_e( 'Email Domain Health Checker', EDHSC_TEXT_DOMAIN ); ?></h1>
        <p>
            <?php
            /* translators: Description of the plugin features */
            esc_html_e(
                'This all-in-one Email Domain Health and Security Checker analyzes critical records like MX (ensuring delivery), SPF, DKIM, and DMARC (preventing spoofing). It also checks MTA-STS for secure connections and BIMI for brand recognition and a host of other checks for a healthy system.',
                EDHSC_TEXT_DOMAIN
            );
            ?>
        </p>
        <p>
            <?php esc_html_e( 'Use shortcode', EDHSC_TEXT_DOMAIN ); ?>
            <span
                id="copy_shortcode"
                style="font-size:20px;background-color:#ffffff;padding:0 5px;border:1px dashed #bbbbbb;cursor:pointer;"
            >[edhsc]</span>
            <?php esc_html_e( 'to render it anywhere you want.', EDHSC_TEXT_DOMAIN ); ?>
        </p>
        <form method="post" action="options.php">
            <?php
            settings_fields( 'edhsc_settings_group' );
            do_settings_sections( 'edhsc-settings' );
            submit_button();
            ?>
        </form>
        <script>
        document.getElementById('copy_shortcode').addEventListener('click', function() {
            navigator.clipboard.writeText('[edhsc]').then(() => {
                const original = this.innerHTML;
                this.innerHTML = '<?php echo esc_js( __( 'Copied!', EDHSC_TEXT_DOMAIN ) ); ?>';
                this.style.color = 'green';
                setTimeout(() => {
                    this.innerHTML = original;
                    this.style.color = '#3c434a';
                }, 1000);
            }).catch(err => {
                console.error('<?php echo esc_js( __( 'Failed to copy:', EDHSC_TEXT_DOMAIN ) ); ?>', err);
            });
        });
        </script>
    </div>
    <?php
}

/**
 * Register plugin settings.
 */
function edhsc_register_settings() {
    register_setting( 'edhsc_settings_group', 'edhsc_settings' );
    add_settings_section(
        'edhsc_general_settings',
        __( 'General Settings', EDHSC_TEXT_DOMAIN ),
        null,
        'edhsc-settings'
    );
    add_settings_field(
        'enable_summary_score',
        __( 'Enable Summary and Score', EDHSC_TEXT_DOMAIN ),
        'edhsc_enable_summary_score_cb',
        'edhsc-settings',
        'edhsc_general_settings'
    );
}
add_action( 'admin_init', 'edhsc_register_settings' );

/**
 * Checkbox callback.
 */
function edhsc_enable_summary_score_cb() {
    $options = get_option( 'edhsc_settings' );
    $checked = isset( $options['enable_summary_score'] ) ? 'checked' : '';
    printf(
        '<input type="checkbox" id="enable_summary_score" name="edhsc_settings[enable_summary_score]" value="1" %s />',
        $checked
    );
}
add_action('admin_init', 'edhsc_register_settings');

/**
 * Cleanup options on uninstall.
 */
register_uninstall_hook(__FILE__, 'edhsc_plugin_cleanup');
function edhsc_plugin_cleanup() {
    delete_option('edhsc_settings');
}

