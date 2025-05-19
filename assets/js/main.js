function isSummaryEnabled() {
    return document.getElementById('summary-container') !== null;
}

document.addEventListener('DOMContentLoaded', function () {
    
        document.getElementById('validatorForm').addEventListener('submit', function (event) {
        event.preventDefault();
        const rawDomain = document.getElementById('domainInput').value;
        const domain = extractDomain(rawDomain);
        const dkimSelector = document.getElementById('dkimSelectorInput').value || 'default';
        
        if (!domain) {
            showError( edhscData.strings.invalidFormat );
            return;
        }

        hideError();
        validateMxRecord(domain, dkimSelector);
    });

    /**
     * Extracts the domain name from a given input.
     * Accepts inputs like:
     *   - example.com
     *   - www.example.com
     *   - https://example.com/
     *   - https://www.example.com/
     *
     * @param {string} input The user-entered string.
     * @return {string|null} Returns the normalized domain (without www) or null if extraction fails.
     */
    function extractDomain(input) {
        input = input.trim();
        if (!input) {
            return null;
        }
        try {
            let url;
            // Check if the input starts with http:// or https://
            if (/^https?:\/\//i.test(input)) {
                url = new URL(input);
            } else {
                // Prepend http:// to parse non-scheme inputs (including www.)
                url = new URL('http://' + input);
            }
            let domain = url.hostname;
            // Remove 'www.' prefix if it exists
            if (domain.toLowerCase().startsWith('www.')) {
                domain = domain.slice(4);
            }
            return domain;
        } catch (e) {
            return null;
        }
    }

    function validateMxRecord(domain, dkimSelector) {
        fetch(edhscData.ajaxurl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: `action=validate_mx_record&domain=${encodeURIComponent(domain)}&nonce=${encodeURIComponent(edhscData.nonce)}`

        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    validateDNS(domain, dkimSelector);
                    checkBlacklist(domain);
                    handleDnsChecks(domain);
                    hideError();
                } else {
                    showError( edhscData.strings.mxError );
                }
            })
            .catch(error => {
                console.error('Error:', error);
                showError( edhscData.strings.mxFetchError );
            });
    }

    function hideError() {
        const errorDiv = document.querySelector('.main-error');
        errorDiv.style.display = 'none';
    }

    function showError(message) {
        const errorDiv = document.querySelector('.main-error');
        errorDiv.style.display = 'block';
        errorDiv.textContent = message;
    }

    const records = document.querySelectorAll('.record');
    records.forEach(record => {
        record.addEventListener('click', function (event) {
            if (event.target === this || (!event.target.closest('table') && !event.target.closest('.scrollable-table-wrapper') && !event.target.closest('.record-text'))) {
                if (this.classList.contains('expanded')) {
                    this.classList.remove('expanded');
                    this.classList.add('collapsed');
                } else {
                    this.classList.add('expanded');
                    this.classList.remove('collapsed');
                }
            }
        });
    });
});

let checksResults = {};

function validateDNS(domain, dkimSelector) {
    const recordDivs = document.querySelectorAll('.record');
    recordDivs.forEach(div => {
        const loader = div.querySelector('.loader');
        loader.style.display = 'inline';
    });

    fetch(edhscData.ajaxurl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `action=validate_dns_records&domain=${encodeURIComponent(domain)}&dkimSelector=${encodeURIComponent(dkimSelector)}&nonce=${encodeURIComponent(edhscData.nonce)}`
    })

        .then(response => response.json())
        .then(data => {
            ['mxRecord', 'spfRecord', 'dkimRecord', 'dmarcRecord', 'mtaStsRecord', 'bimiRecord'].forEach(recordId => {
                updateRecordStatus(recordId, data[recordId]);
            });
        });
}

function handleDnsChecks(domain) {
    const totalChecks = 11;
    checksResults = {};

    for (let i = 1; i <= totalChecks; i++) {
        const checkElement = document.getElementById(`check${i}`);
        if (!checkElement) {
            console.warn(`Check element #${i} does not exist.`);
            continue;
        }
        const resultIcon = checkElement.querySelector('.result-icon');
        if (!resultIcon) {
            console.warn(`Result icon for check #${i} does not exist.`);
            continue;
        }

        resultIcon.style.display = 'inline';
        resultIcon.innerHTML = `<img src="${edhscData.images.loader}" class="loader">`;

        fetch(edhscData.ajaxurl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: `action=dns_check&domain=${domain}&check=${i}&nonce=${encodeURIComponent(edhscData.nonce)}`
        })
            .then(response => response.json())
            .then(data => {
                resultIcon.innerHTML = data.passed ? `<img src="${edhscData.images.tick}" class="tick">` : `<img src="${edhscData.images.cross}" class="cross">`;
                resultIcon.classList.toggle('valid', data.passed);
                checksResults[`check${i}`] = data.passed;

                // Update the summary for the record associated with this check
                updateSummaryFromChecks();
            })
            .catch(error => {
                console.error('Error:', error);
                resultIcon.innerHTML = `<img src="${edhscData.images.cross}" class="cross">`;
            });
    }
}



function updateRecordStatus(recordId, recordData) {
    const recordDiv = document.getElementById(recordId);
    const loader = recordDiv.querySelector('.loader');
    const detailsSpan = recordDiv.querySelector('.details');

    clearPreviousResults(recordDiv);

    const recordText = document.createElement('pre');
    recordText.className = 'record-text';

    if (loader) loader.style.display = 'none';
    detailsSpan.style.display = 'flex';
    if (recordData.available) {
        recordDiv.classList.add('green');
        recordDiv.classList.remove('unavailable');
        if (recordId === 'mxRecord') {
            recordText.textContent = recordData.details.map(detail => `${detail.hostname} (Priority: ${detail.pref})`).join(', ');
        } else {
            recordText.textContent = recordData.record;
        }
    } else {
        recordDiv.classList.add('unavailable');
        recordDiv.classList.remove('green');
        recordText.textContent = edhscData.strings.noRecord;
    }
    recordDiv.appendChild(recordText);

    if (recordData.available && recordData.details && recordData.details.length) {
        const tableGeneratorFunction = {
            'mxRecord': generateMxRecordTable,
            'spfRecord': generateSpfRecordTable,
            'dmarcRecord': generateDmarcRecordTable,
            'dkimRecord': generateDkimRecordTable,
            'mtaStsRecord': generateMtaStsRecordTable,
            'bimiRecord': generateBimiRecordTable
        }[recordId];

        if (tableGeneratorFunction) {
            const table = tableGeneratorFunction(recordData.details);
            recordDiv.appendChild(table);
        }
    }

    updateSummary(recordId, recordData);
}

function clearPreviousResults(recordDiv) {
    const existingTable = recordDiv.querySelector('.scrollable-table-wrapper');
    if (existingTable) {
        recordDiv.removeChild(existingTable);
    }
    const existingText = recordDiv.querySelector('.record-text');
    if (existingText) {
        recordDiv.removeChild(existingText);
    }
}

// Generate a table for MX record details
function generateMxRecordTable(details) {
    var table = document.createElement('table');
    table.id = 'mxRecordTable';
    var divWrapper = document.createElement('div');
    divWrapper.className = 'scrollable-table-wrapper';
    divWrapper.appendChild(table);
    table.innerHTML = 
        '<tr>' +
            '<th>' + edhscData.strings.thPref + '</th>' +
            '<th>' + edhscData.strings.thHostname + '</th>' +
            '<th>' + edhscData.strings.thIpAddress + '</th>' +
            '<th>' + edhscData.strings.thMxReverseLookup + '</th>' +
        '</tr>';
    details.forEach(function (detail) {
        var row = table.insertRow(-1);
        var prefCell = row.insertCell(0);
        var hostCell = row.insertCell(1);
        var ipCell = row.insertCell(2);
        var reverseLookupCell = row.insertCell(3);
        prefCell.textContent = detail.pref;
        hostCell.textContent = detail.hostname;
        ipCell.textContent = detail.ip;
        reverseLookupCell.textContent = detail.mxReverseLookup;
    });
    return divWrapper;
}

// Generate a table for SPF record details
function generateSpfRecordTable(details) {
    var table = document.createElement('table');
    table.id = 'spfRecordTable';
    var divWrapper = document.createElement('div');
    divWrapper.className = 'scrollable-table-wrapper';
    divWrapper.appendChild(table);
    table.innerHTML = 
        '<tr>' +
            '<th>' + edhscData.strings.thQualifier   + '</th>' +
            '<th>' + edhscData.strings.thMechanism   + '</th>' +
            '<th>' + edhscData.strings.thValue       + '</th>' +
            '<th>' + edhscData.strings.thDescription + '</th>' +
        '</tr>';
    details.forEach((detail, index) => {
        var row = table.insertRow();
        var cellPrefix = row.insertCell();
        var cellType = row.insertCell();
        var cellValue = row.insertCell();
        var cellDescription = row.insertCell();

        cellPrefix.textContent = index === 0 ? '' : detail.prefix;
        cellType.textContent = detail.type;
        cellValue.textContent = detail.value;
        cellDescription.textContent = detail.description;
    });
    return divWrapper;
}

// Generate a table for DMARC record details
function generateDmarcRecordTable(details) {
    var table = document.createElement('table');
    table.id = 'dmarcRecordTable';
    var divWrapper = document.createElement('div');
    divWrapper.className = 'scrollable-table-wrapper';
    divWrapper.appendChild(table);
    table.innerHTML =
        '<tr>' +
            '<th>' + edhscData.strings.thTag         + '</th>' +
            '<th>' + edhscData.strings.thValue       + '</th>' +
            '<th>' + edhscData.strings.thName        + '</th>' +
            '<th>' + edhscData.strings.thDescription + '</th>' +
        '</tr>';
    details.forEach(detail => {
        var row = table.insertRow();
        var cellTag = row.insertCell();
        var cellValue = row.insertCell();
        var cellName = row.insertCell();
        var cellDescription = row.insertCell();

        cellTag.textContent = detail.tag;
        cellValue.textContent = detail.value;
        cellName.textContent = detail.name;
        cellDescription.textContent = detail.description;
    });
    return divWrapper;
}

// Generate a table for DKIM record details
function generateDkimRecordTable(details) {
    var table = document.createElement('table');
    table.id = 'dkimRecordTable';
    var divWrapper = document.createElement('div');
    divWrapper.className = 'scrollable-table-wrapper';
    divWrapper.appendChild(table);
    table.innerHTML =
        '<tr>' +
            '<th>' + edhscData.strings.thTag   + '</th>' +
            '<th>' + edhscData.strings.thName  + '</th>' +
            '<th>' + edhscData.strings.thValue + '</th>' +
        '</tr>';
    details.forEach(detail => {
        var row = table.insertRow();
        var cellTag = row.insertCell();
        var cellName = row.insertCell();
        var cellValue = row.insertCell();

        const tagToName = {
            'v': edhscData.strings.dkimVersion,
            'k': edhscData.strings.dkimKeyType,
            'p': edhscData.strings.dkimPublicKey,
        };

        cellTag.textContent = detail.tag;
        cellName.textContent = tagToName[detail.tag] || detail.tag;
        cellValue.textContent = detail.value;
    });
    return divWrapper;
}

function generateMtaStsRecordTable(details) {
    var table = document.createElement('table');
    table.id = 'mtaStsRecordTable';
    var divWrapper = document.createElement('div');
    divWrapper.className = 'scrollable-table-wrapper';
    divWrapper.appendChild(table);
    table.innerHTML =
        '<tr>' +
            '<th>' + edhscData.strings.thTag         + '</th>' +
            '<th>' + edhscData.strings.thValue       + '</th>' +
            '<th>' + edhscData.strings.thName        + '</th>' +
            '<th>' + edhscData.strings.thDescription + '</th>' +
        '</tr>';

    details.forEach(detail => {
        var row = table.insertRow(-1);
        var cellTag = row.insertCell(0);
        var cellValue = row.insertCell(1);
        var cellName = row.insertCell(2);
        var cellDescription = row.insertCell(3);
        cellTag.textContent = detail.tag;
        cellValue.textContent = detail.value;
        cellName.textContent = detail.name;
        cellDescription.textContent = detail.description;
    });

    return divWrapper;
}

function generateBimiRecordTable(details) {
    var table = document.createElement('table');
    table.id = 'bimiRecordTable';
    var divWrapper = document.createElement('div');
    divWrapper.className = 'scrollable-table-wrapper';
    divWrapper.appendChild(table);
    table.innerHTML =
        '<tr>' +
            '<th>' + edhscData.strings.thTag         + '</th>' +
            '<th>' + edhscData.strings.thValue       + '</th>' +
            '<th>' + edhscData.strings.thName        + '</th>' +
            '<th>' + edhscData.strings.thDescription + '</th>' +
        '</tr>';

    details.forEach(detail => {
        var row = table.insertRow();
        var cellTag = row.insertCell();
        var cellValue = row.insertCell();
        var cellName = row.insertCell();
        var cellDescription = row.insertCell();

        cellTag.textContent = detail.tag;
        cellValue.textContent = detail.value;
        cellName.textContent = detail.name;
        cellDescription.textContent = detail.description;
    });

    return divWrapper;
}


function checkBlacklist(input) {
    const resultContainers = document.querySelectorAll('.result-container');
    resultContainers.forEach(container => {
        container.querySelector('.loader-icon').style.display = 'inline';
        container.querySelector('.check-icon').style.display = 'none';
        container.querySelector('.close-icon').style.display = 'none';
    });

    fetch(edhscData.ajaxurl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `action=check_blacklist&input=${encodeURIComponent(input)}&nonce=${encodeURIComponent(edhscData.nonce)}`
    })
        .then(response => response.json())
        .then(data => {
            if (!data.success) {
                showError(data.data);
                return;
            }

            const blocklistResults = {
                'spamcop': 'spamcop-result',
                'sibl': 'sibl-result',
                'barracudacentral': 'barracudacentral-result',
                's5h': 's5h-result',
                'psbl': 'psbl-result',
                'bl': 'bl-result',
                'ip-spamcop': 'ip-spamcop-result',
                'ip-sibl': 'ip-sibl-result',
                'ip-barracudacentral': 'ip-barracudacentral-result',
                'ip-s5h': 'ip-s5h-result',
                'ip-psbl': 'ip-psbl-result',
                'ip-bl': 'ip-bl-result',
                'ip-dnsbl': 'ip-dnsbl-result'
            };

            Object.keys(blocklistResults).forEach(key => {
                const resultContainer = document.getElementById(blocklistResults[key]);
                resultContainer.querySelector('.loader-icon').style.display = 'none';
                const blackListDiv = document.querySelectorAll('.blocklistResults');
                blackListDiv.forEach(div => {
                div.querySelector('.details').style.display = 'flex';
                });
                if (data.data[key]) {
                    resultContainer.classList.add('unavailable');
                    resultContainer.classList.remove('green');
                    resultContainer.querySelector('.close-icon').style.display = 'inline';
                    resultContainer.querySelector('.check-icon').style.display = 'none';
                } else {
                    resultContainer.classList.add('green');
                    resultContainer.classList.remove('unavailable');
                    resultContainer.querySelector('.check-icon').style.display = 'inline';
                    resultContainer.querySelector('.close-icon').style.display = 'none';
                }
            });

            
            updateSummaryBlacklist(data.data);
            updateSummaryIPBlacklist(data.data);
            
        });
}

function sprintf(template, value) {
    return template.replace('%s', value);
}

function updateSummary(recordId, recordData) {
    
    const summaryDiv = document.getElementById(`summary${recordId.charAt(0).toUpperCase() + recordId.slice(1)}`);
    if (!summaryDiv) {
        console.warn(`Summary div summary${recordId.charAt(0).toUpperCase() + recordId.slice(1)} does not exist.`);
        return;
    }

    const summaryIcons = summaryDiv.querySelectorAll('.summary-icon');
    const summaryText = summaryDiv.querySelector('.summary-text');

    summaryIcons.forEach(icon => icon.style.display = 'none');

    const recordName = recordId.replace('Record', '').toUpperCase();

    if ( recordData.available ) {
        summaryIcons[0].style.display = 'inline';
        summaryText.textContent = sprintf(
            edhscData.strings.summarySetupOk,
            recordName
        );
    } else {
        summaryIcons[2].style.display = 'inline';
        summaryText.textContent = sprintf(
            edhscData.strings.summaryNeedsSetup,
            recordName
        );
    }
    
    updateSummaryFromChecks();
   
}


function updateSummaryFromChecks() {
    
    const checksSummary = {
        mxRecord: [1, 10],
        spfRecord: [2, 5, 6],
        dkimRecord: [7],
        dmarcRecord: [3, 8, 11],
        mtaStsRecord: [4, 9],
        bimiRecord: []
    };

    Object.keys(checksSummary).forEach(recordId => {
        const checkIds = checksSummary[recordId];
        const recordDiv = document.getElementById(recordId);
        const statusSpan = recordDiv.querySelector('.status');

        if (checkIds.length > 0) {
            const allValid = checkIds.every(checkId => checksResults[`check${checkId}`]);
            const anyInvalid = checkIds.some(checkId => !checksResults[`check${checkId}`]);


            const recordName = recordId.replace('Record', '').toUpperCase();

            if (allValid && recordDiv.classList.contains('green')) {
                statusSpan.textContent = edhscData.strings.statusGood;
                statusSpan.style.color = '#fff';
                statusSpan.style.backgroundColor = '#38b26d';
                if (!isSummaryEnabled()) return;
                const summaryDiv = document.getElementById(`summary${recordId.charAt(0).toUpperCase() + recordId.slice(1)}`);

                if (!summaryDiv) {
                    console.warn(`Summary div summary${recordId.charAt(0).toUpperCase() + recordId.slice(1)} does not exist.`);
                    return;
                }

                const summaryIcons = summaryDiv.querySelectorAll('.summary-icon');
                const summaryText = summaryDiv.querySelector('.summary-text');

                summaryIcons.forEach(icon => icon.style.display = 'none');
                summaryIcons[0].style.display = 'inline';
                summaryText.textContent = edhscData.strings.summarySetupOk.replace('%s', recordName);
            } else if (anyInvalid && recordDiv.classList.contains('green')) {
                statusSpan.style.color = '#fff';
                statusSpan.textContent = edhscData.strings.statusWarning;
                statusSpan.style.backgroundColor = '#ffae00';
                if (!isSummaryEnabled()) return;
                const summaryDiv = document.getElementById(`summary${recordId.charAt(0).toUpperCase() + recordId.slice(1)}`);

                if (!summaryDiv) {
                    console.warn(`Summary div summary${recordId.charAt(0).toUpperCase() + recordId.slice(1)} does not exist.`);
                    return;
                }

                const summaryIcons = summaryDiv.querySelectorAll('.summary-icon');
                const summaryText = summaryDiv.querySelector('.summary-text');

                summaryIcons.forEach(icon => icon.style.display = 'none');
                summaryIcons[1].style.display = 'inline';
                summaryText.textContent = edhscData.strings.summaryNeedsAttention.replace('%s', recordName);
            } else if (!recordDiv.classList.contains('green')) {
                statusSpan.style.color = '#fff';
                statusSpan.textContent = edhscData.strings.statusError;
                statusSpan.style.backgroundColor = '#d65757';
                if (!isSummaryEnabled()) return;
                const summaryDiv = document.getElementById(`summary${recordId.charAt(0).toUpperCase() + recordId.slice(1)}`);

                if (!summaryDiv) {
                    console.warn(`Summary div summary${recordId.charAt(0).toUpperCase() + recordId.slice(1)} does not exist.`);
                    return;
                }

                const summaryIcons = summaryDiv.querySelectorAll('.summary-icon');
                const summaryText = summaryDiv.querySelector('.summary-text');

                summaryIcons.forEach(icon => icon.style.display = 'none');
                summaryIcons[2].style.display = 'inline';
                summaryText.textContent = edhscData.strings.summaryNeedsSetup.replace('%s', recordName);
            }
        } else if (document.getElementById(recordId).classList.contains('green')) {
            const recordName = recordId.replace('Record', '').toUpperCase();
            statusSpan.textContent = edhscData.strings.statusGood;
            statusSpan.style.color = '#fff';
            statusSpan.style.backgroundColor = '#38b26d';
            if (!isSummaryEnabled()) return;
            const summaryDiv = document.getElementById(`summary${recordId.charAt(0).toUpperCase() + recordId.slice(1)}`);

            if (!summaryDiv) {
                console.warn(`Summary div summary${recordId.charAt(0).toUpperCase() + recordId.slice(1)} does not exist.`);
                return;
            }

            const summaryIcons = summaryDiv.querySelectorAll('.summary-icon');
            const summaryText = summaryDiv.querySelector('.summary-text');

            summaryIcons.forEach(icon => icon.style.display = 'none');
            summaryIcons[0].style.display = 'inline';
            summaryText.textContent = edhscData.strings.summarySetupOk.replace('%s', recordName);
        } else {
            const recordName = recordId.replace('Record', '').toUpperCase();
            statusSpan.style.color = '#fff';
            statusSpan.textContent = edhscData.strings.statusError;
            statusSpan.style.backgroundColor = '#d65757';
            if (!isSummaryEnabled()) return;
            const summaryDiv = document.getElementById(`summary${recordId.charAt(0).toUpperCase() + recordId.slice(1)}`);

            if (!summaryDiv) {
                console.warn(`Summary div summary${recordId.charAt(0).toUpperCase() + recordId.slice(1)} does not exist.`);
                return;
            }

            const summaryIcons = summaryDiv.querySelectorAll('.summary-icon');
            const summaryText = summaryDiv.querySelector('.summary-text');

            summaryIcons.forEach(icon => icon.style.display = 'none');
            summaryIcons[2].style.display = 'inline';
            summaryText.textContent = edhscData.strings.summaryNeedsSetup.replace('%s', recordName);
        }
    });

    calculateOverallScore();
}

function updateSummaryBlacklist(data) {
    
    const blacklistDiv = document.getElementById('emailBlacklist');
    blacklistDiv.querySelector('.loader').style.display = 'none';
    const statusSpan = blacklistDiv.querySelector('.status');

    const values = Object.values(data);
    const allPassed = values.every(value => !value);
    const partiallyPassed = values.some(value => value);

    if (allPassed) {
        statusSpan.textContent = edhscData.strings.statusGood;
        statusSpan.style.color = '#fff';
        statusSpan.style.backgroundColor = '#38b26d';
    } else if (partiallyPassed) {
        statusSpan.style.color = '#fff';
        statusSpan.textContent = edhscData.strings.statusWarning;
        statusSpan.style.backgroundColor = '#ffae00';
    } else {
        statusSpan.style.color = '#fff';
        statusSpan.textContent = edhscData.strings.statusError;
        statusSpan.style.backgroundColor = '#d65757';
    }
    
    //if (!isSummaryEnabled()) return;
    
    const summaryDiv = document.getElementById('summaryEmailBlacklist');
    if (!summaryDiv) {
        console.warn('Summary div summaryEmailBlacklist does not exist.');
        return;
    }

    const summaryIcons = summaryDiv.querySelectorAll('.summary-icon');
    const summaryText = summaryDiv.querySelector('.summary-text');

    summaryIcons.forEach(icon => icon.style.display = 'none');
    
    if (allPassed) {
        summaryIcons[0].style.display = 'inline';
        summaryText.textContent = edhscData.strings.summaryBlacklistClear;
    } else if (partiallyPassed) {
        summaryIcons[1].style.display = 'inline';
        summaryText.textContent = edhscData.strings.summaryBlacklistPartial;
    } else {
        summaryIcons[2].style.display = 'inline';
        summaryText.textContent = edhscData.strings.summaryBlacklistFailed;
    }

    calculateOverallScore();
}

function updateSummaryIPBlacklist(data) {
    
    const blacklistDiv = document.getElementById('ipBlacklist');
    blacklistDiv.querySelector('.loader').style.display = 'none';
    const statusSpan = blacklistDiv.querySelector('.status');

    const values = Object.values(data);
    const allPassed = values.every(value => !value);
    const partiallyPassed = values.some(value => value);
    
    if (allPassed) {
        statusSpan.textContent = edhscData.strings.statusGood;
        statusSpan.style.color = '#fff';
        statusSpan.style.backgroundColor = '#38b26d';
    } else if (partiallyPassed) {
        statusSpan.style.color = '#fff';
        statusSpan.textContent = edhscData.strings.statusWarning;
        statusSpan.style.backgroundColor = '#ffae00';
    } else {
        statusSpan.style.color = '#fff';
        statusSpan.textContent = edhscData.strings.statusError;
        statusSpan.style.backgroundColor = '#d65757';
    }
    
    // if (!isSummaryEnabled()) return;
    
    const summaryDiv = document.getElementById('summaryIpBlacklist');
    if (!summaryDiv) {
        console.warn('Summary div summaryIpBlacklist does not exist.');
        return;
    }

    const summaryIcons = summaryDiv.querySelectorAll('.summary-icon');
    const summaryText = summaryDiv.querySelector('.summary-text');

    summaryIcons.forEach(icon => icon.style.display = 'none');

    if (allPassed) {
        summaryIcons[0].style.display = 'inline';
        summaryText.textContent = edhscData.strings.summaryIPBlacklistClear;
    } else if (partiallyPassed) {
        summaryIcons[1].style.display = 'inline';
        summaryText.textContent = edhscData.strings.summaryIPBlacklistPartial;
    } else {
        summaryIcons[2].style.display = 'inline';
        summaryText.textContent = edhscData.strings.summaryIPBlacklistFailed;
    }

    calculateOverallScore();
}

function calculateOverallScore() {
    
    let score = 0;

    const tickPoints = {
        summarySpfRecord: 30,
        summaryDkimRecord: 15,
        summaryDmarcRecord: 15,
        summaryMtaStsRecord: 10,
        summaryBimiRecord: 5,
        summaryEmailBlacklist: 15,
        summaryIpBlacklist: 10
    };

    const mxRecordDiv = document.getElementById('summaryMxRecord');
    if (mxRecordDiv && mxRecordDiv.querySelector('.tick[style="display: inline;"]')) {
        for (const [summaryId, points] of Object.entries(tickPoints)) {
            const summaryDiv = document.getElementById(summaryId);
            if (summaryDiv && summaryDiv.querySelector('.tick[style="display: inline;"]')) {
                score += points;
            }
        }
    }

    const scoreDiv = document.getElementById('overallScore');
    if (scoreDiv) {
        scoreDiv.textContent = `${score}/100`;
        if (score <= 50) {
            scoreDiv.style.color = 'red';
        } else if (score <= 75) {
            scoreDiv.style.color = 'orange';
        } else {
            scoreDiv.style.color = 'green';
        }
    }

}
