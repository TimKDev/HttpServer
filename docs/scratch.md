## Idee 
- Die IP Pakete werden empfangen und geparst. Danach packen wir sie in ein Arrays.
    - Nicht frakmentierte Pakete kommen in ein Array. 
    - Pakete die frakmentiert sind und noch nicht vollständig angekommen, sind in dem anderen Array
- Jedes Mal wenn ein neues IP Paket empfangen wurde, überprüfen wir 