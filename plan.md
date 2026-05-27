 - pipeline-health.json with per-feed last-run status → displayed in UI                                            
  - OG image + meta tags for sharing                                                                                
  - Mobile layout (collapsed sidebar, touch-rotate globe)                                                           
                                                                                                                    
  ---                                                                                                               
  Senior-Engineer Signals in the Design                                                                             
                                                                                                                    
  1. TLP labeling on all feed data — standard OSINT etiquette (all sources here are TLP:WHITE/GREEN)                
  2. Provenance chain — every event carries feed + source URL, no opaque blobs                                      
  3. Zod schema validation at pipeline output boundary — catches API drift before it corrupts the frontend          
  4. Confidence/severity scoring — not raw counts but normalized 1-4 scale with rationale                           
  5. MITRE ATT&CK TTP mapping — connects observable indicators to adversary behavior model                          
  6. ASN enrichment — identifies hosting/cloud providers as infrastructure patterns                                 
  7. Rate limiting + exponential backoff in pipeline (httpx with tenacity)                                          
  8. Pipeline observability — pipeline-health.json with per-feed status, latency, last error                        
  9. Data versioning — timestamped snapshots kept for 7 days (git history)                                          
  10. WebWorker offloading — data filtering never blocks the render loop                                            
                                                                                                                    
  ---                                                                                                               
  DNS Setup (CNAME)                                                                                                 
                                                                                                                    
  In your domain registrar (francescocitti.com DNS):                                                                
  threatmap.francescocitti.com  CNAME  <your-github-username>.github.io                                             
  Then a CNAME file in the repo root containing threatmap.francescocitti.com.                                       
                                                                                                                    
  ---                                                                                                               
  Ready to implement? I'd suggest starting with Phase 1 — the scaffold + Feodo pipeline + basic globe — so you have 
  something live on threatmap.francescocitti.com within the first session. Confirm and I'll start building.   