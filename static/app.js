// Aspetta che tutto l'HTML sia caricato prima di eseguire lo script
document.addEventListener('DOMContentLoaded', () => {

    // --- 1. Trova tutti gli elementi interattivi ---
    const elements = {
        tableBody: document.getElementById('alerts-body'),
        searchInput: document.getElementById('q'),
        countChip: document.getElementById('count'),
        emptyState: document.getElementById('empty'),
        liveToggleBtn: document.getElementById('liveToggle'),
        refreshBtn: document.getElementById('refresh')
    };

    // --- 2. Stato dell'applicazione ---
    let state = {
        isLive: true,       // Il "Live ON/OFF" è attivo di default
        searchTerm: '',     // Il testo della ricerca
        allAlerts: []       // Dove salviamo tutti gli allarmi presi dal server
    };

  

    /**
     * Mappa il motivo dell'allarme a una classe CSS per il badge colorato.
     */
    function mapReasonToBadge(reason) {
        const r = reason.toLowerCase();
        if (r.includes('syn flood')) return 'b-bad'; // Rosso
        if (r.includes('sql') || r.includes('traversal')) return 'b-warn'; // Arancione
        if (r.includes('scan')) return 'b-warn'; // Giallo
        if (r.includes('porta')) return 'b-info'; // Blu
        return ''; // Default
    }

    /**
     * Mappa il motivo a un'etichetta più pulita.
     */
    function formatReason(reason) {
        if (reason.includes('Potenziale')) return reason.replace('Potenziale ', '');
        return reason;
    }

    // --- 4. Funzione di Rendering Principale ---

    /**
     * Pulisce la tabella e la ridisegna in base allo stato attuale.
     */
    function renderTable() {
        // Filtra gli allarmi in base al termine di ricerca
        const searchTerm = state.searchTerm.toLowerCase();
        const filteredAlerts = state.allAlerts.filter(alert => {
            // Controlla su tutti i campi dell'allarme
            return Object.values(alert).some(value => 
                String(value).toLowerCase().includes(searchTerm)
            );
        });

        // Aggiorna il contatore
        elements.countChip.textContent = `${filteredAlerts.length} risultati`;

        // Mostra/nascondi lo stato "vuoto"
        if (filteredAlerts.length === 0) {
            elements.emptyState.style.display = 'block';
            elements.tableBody.innerHTML = '';
        } else {
            elements.emptyState.style.display = 'none';
            // Costruisci l'HTML della tabella
            elements.tableBody.innerHTML = filteredAlerts
                .map(alert => `
                    <tr>
                        <td class="mono">${alert.timestamp}</td>
                        <td>
                            <span class="badge ${mapReasonToBadge(alert.alert_reason)}">
                                ${formatReason(alert.alert_reason)}
                            </span>
                        </td>
                        <td class="mono">${alert.source_ip}</td>
                        <td class="mono">${alert.dest_port}</td>
                        <td class="mono">${alert.details}</td>
                        <td>${alert.virustotal_summary}</td>
                    </tr>
                `)
                .reverse() // Mostra i più nuovi in cima
                .join(''); // Unisce tutte le righe in un'unica stringa
        }
    }

    // --- 5. Funzione di Fetch dei Dati ---

    /**
     * Contatta l'API di FastAPI per prendere i nuovi allarmi.
     */
    async function fetchAlerts() {
        // Non fare nulla se il "Live" è in pausa
        if (!state.isLive && state.allAlerts.length > 0) {
            return;
        }

        try {
            // Questo endpoint DEVE corrispondere al tuo @app.get() in dashboard.py
            const response = await fetch('/api/alerts');
            if (!response.ok) return; // Gestisci errori

            const data = await response.json();
            state.allAlerts = data.alerts; // Aggiorna la nostra "memoria"
            
            // Ridisegna la tabella con i nuovi dati (e il filtro attuale)
            renderTable();

        } catch (e) {
            console.error("Errore nel fetch degli allarmi:", e);
        }
    }

    // --- 6. Collegamento degli Eventi ---

    // Filtro di ricerca
    elements.searchInput.addEventListener('input', (e) => {
        state.searchTerm = e.target.value;
        // Non serve una nuova fetch, ridisegna solo con i dati che abbiamo
        renderTable(); 
    });

    // Bottone Live ON/OFF
    elements.liveToggleBtn.addEventListener('click', () => {
        state.isLive = !state.isLive; // Inverti lo stato
        elements.liveToggleBtn.textContent = state.isLive ? 'Live ON' : 'Live OFF';
        elements.liveToggleBtn.setAttribute('aria-pressed', state.isLive);
        elements.liveToggleBtn.classList.toggle('primary', state.isLive);
        
        // Se lo riattivi, fai subito una fetch
        if (state.isLive) {
            fetchAlerts();
        }
    });

    // Bottone Aggiorna Manuale
    elements.refreshBtn.addEventListener('click', async () => {
        // Forza una fetch anche se il live è spento
        const wasLive = state.isLive;
        state.isLive = true;
        await fetchAlerts();
        state.isLive = wasLive; // Rimetti lo stato com'era
    });

    // --- 7. Avvio ---
    fetchAlerts(); // Carica i dati la prima volta
    setInterval(fetchAlerts, 2000); // Polling: aggiorna i dati ogni 2 secondi
});