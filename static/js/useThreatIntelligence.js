// static/js/useThreatIntelligence.js
import { useState, useCallback, useRef } from 'react';

export const useThreatIntelligence = () => {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [processed, setProcessed] = useState(0);
  const [total, setTotal] = useState(0);
  const [threatsFound, setThreatsFound] = useState(0);
  const [error, setError] = useState(null);
  
  const workerRef = useRef(null);

  const checkThreatIntelligence = useCallback(async (forceRefresh = false) => {
    // Controlla cache (5 minuti) se non è forzato
    if (!forceRefresh) {
      const cached = localStorage.getItem('threatIntelligenceCache');
      const cacheTime = localStorage.getItem('threatIntelligenceCacheTime');
      
      if (cached && cacheTime && (Date.now() - parseInt(cacheTime)) < 300000) {
        setData(JSON.parse(cached));
        return;
      }
    }

    // Reset stati
    setLoading(true);
    setProgress(0);
    setProcessed(0);
    setTotal(0);
    setThreatsFound(0);
    setError(null);
    setData(null);

    // Crea nuovo worker - MODIFICA IL PERCORSO
    if (workerRef.current) {
      workerRef.current.terminate();
    }

    // MODIFICA IMPORTANTE: Percorso corretto per il worker
    workerRef.current = new Worker('/static/js/threatIntelligence.worker.js');

    workerRef.current.onmessage = (e) => {
      switch (e.data.type) {
        case 'PROGRESS':
          setProgress(e.data.progress);
          setProcessed(e.data.processed);
          setTotal(e.data.total);
          setThreatsFound(e.data.threatsFound);
          break;
          
        case 'COMPLETE':
          setData(e.data.data);
          setLoading(false);
          setProgress(100);
          
          // Salva in cache
          localStorage.setItem('threatIntelligenceCache', JSON.stringify(e.data.data));
          localStorage.setItem('threatIntelligenceCacheTime', Date.now().toString());
          
          // Termina worker
          if (workerRef.current) {
            workerRef.current.terminate();
            workerRef.current = null;
          }
          break;
          
        case 'ERROR':
          setError(e.data.error);
          setLoading(false);
          
          if (workerRef.current) {
            workerRef.current.terminate();
            workerRef.current = null;
          }
          break;
      }
    };

    workerRef.current.onerror = (err) => {
      setError(`Worker error: ${err.message}`);
      setLoading(false);
      
      if (workerRef.current) {
        workerRef.current.terminate();
        workerRef.current = null;
      }
    };

    // Avvia il controllo
    workerRef.current.postMessage({ 
      action: 'CHECK_THREAT_INTELLIGENCE',
      batchSize: 50
    });

  }, []);

  const cancelCheck = useCallback(() => {
    if (workerRef.current) {
      workerRef.current.terminate();
      workerRef.current = null;
      setLoading(false);
      setProgress(0);
    }
  }, []);

  return { 
    data, 
    loading, 
    progress, 
    processed, 
    total, 
    threatsFound, 
    error,
    checkThreatIntelligence,
    cancelCheck
  };
};