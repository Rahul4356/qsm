// sw.js - Service Worker for offline support
const CACHE_NAME = 'qms-v1';
const STATIC_CACHE = 'qms-static-v1';
const API_CACHE = 'qms-api-v1';

const STATIC_ASSETS = [
    '/quantum-messaging-enhanced.html',
    '/favicon.ico'
];

// Install event
self.addEventListener('install', event => {
    console.log('Service Worker installing...');
    event.waitUntil(
        caches.open(STATIC_CACHE)
            .then(cache => {
                console.log('Caching static assets');
                return cache.addAll(STATIC_ASSETS);
            })
            .then(() => self.skipWaiting())
            .catch(error => console.error('Cache installation failed:', error))
    );
});

// Activate event
self.addEventListener('activate', event => {
    console.log('Service Worker activating...');
    event.waitUntil(
        caches.keys().then(cacheNames => {
            return Promise.all(
                cacheNames
                    .filter(name => name.startsWith('qms-') && name !== STATIC_CACHE && name !== API_CACHE)
                    .map(name => {
                        console.log('Deleting old cache:', name);
                        return caches.delete(name);
                    })
            );
        }).then(() => {
            console.log('Service Worker activated');
            return self.clients.claim();
        })
    );
});

// Fetch event
self.addEventListener('fetch', event => {
    const { request } = event;
    const url = new URL(request.url);
    
    // Skip non-GET requests
    if (request.method !== 'GET') return;
    
    // Skip chrome-extension and other non-http requests
    if (!url.protocol.startsWith('http')) return;
    
    // API calls - network first, fallback to cache
    if (url.pathname.startsWith('/api/')) {
        event.respondWith(
            fetch(request)
                .then(response => {
                    // Only cache successful responses
                    if (response.ok && response.status === 200) {
                        const responseClone = response.clone();
                        caches.open(API_CACHE).then(cache => {
                            // Set expiry for API cache (5 minutes)
                            const headers = new Headers(responseClone.headers);
                            headers.set('sw-cache-timestamp', Date.now().toString());
                            const cachedResponse = new Response(responseClone.body, {
                                status: responseClone.status,
                                statusText: responseClone.statusText,
                                headers: headers
                            });
                            cache.put(request, cachedResponse);
                        }).catch(error => console.error('API cache error:', error));
                    }
                    return response;
                })
                .catch(error => {
                    console.log('Network failed, trying cache for API:', url.pathname);
                    return caches.open(API_CACHE).then(cache => {
                        return cache.match(request).then(cached => {
                            if (cached) {
                                // Check if cached response is still valid (5 minutes)
                                const timestamp = cached.headers.get('sw-cache-timestamp');
                                if (timestamp && (Date.now() - parseInt(timestamp)) > 5 * 60 * 1000) {
                                    console.log('Cached API response expired');
                                    cache.delete(request);
                                    return null;
                                }
                                console.log('Serving cached API response');
                                return cached;
                            }
                            return null;
                        });
                    });
                })
        );
        return;
    }
    
    // Static assets - cache first, fallback to network
    event.respondWith(
        caches.match(request)
            .then(cached => {
                if (cached) {
                    console.log('Serving from cache:', url.pathname);
                    return cached;
                }
                
                console.log('Fetching from network:', url.pathname);
                return fetch(request).then(response => {
                    // Cache successful responses for static assets
                    if (response.ok && response.status === 200) {
                        const responseClone = response.clone();
                        caches.open(STATIC_CACHE).then(cache => {
                            cache.put(request, responseClone);
                        }).catch(error => console.error('Static cache error:', error));
                    }
                    return response;
                });
            })
            .catch(error => {
                console.error('Fetch failed:', error);
                // Offline fallback for HTML requests
                if (request.headers.get('accept')?.includes('text/html')) {
                    return caches.match('/quantum-messaging-enhanced.html').then(cached => {
                        if (cached) {
                            console.log('Serving offline fallback');
                            return cached;
                        }
                        // Return a simple offline page if no cache available
                        return new Response(`
                            <!DOCTYPE html>
                            <html>
                            <head>
                                <title>QMS - Offline</title>
                                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                                <style>
                                    body { 
                                        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
                                        display: flex; 
                                        align-items: center; 
                                        justify-content: center; 
                                        min-height: 100vh; 
                                        margin: 0; 
                                        background: #f3f4f6;
                                        text-align: center;
                                    }
                                    .container {
                                        background: white;
                                        padding: 2rem;
                                        border-radius: 0.5rem;
                                        box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
                                        max-width: 400px;
                                    }
                                    .icon { font-size: 3rem; margin-bottom: 1rem; }
                                    h1 { color: #374151; margin-bottom: 1rem; }
                                    p { color: #6b7280; margin-bottom: 2rem; }
                                    button {
                                        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                                        color: white;
                                        border: none;
                                        padding: 0.75rem 1.5rem;
                                        border-radius: 0.5rem;
                                        cursor: pointer;
                                        font-weight: 600;
                                    }
                                    button:hover { opacity: 0.9; }
                                </style>
                            </head>
                            <body>
                                <div class="container">
                                    <div class="icon">📡</div>
                                    <h1>You're Offline</h1>
                                    <p>QMS requires an internet connection. Please check your network and try again.</p>
                                    <button onclick="window.location.reload()">Retry</button>
                                </div>
                            </body>
                            </html>
                        `, {
                            headers: { 'Content-Type': 'text/html' }
                        });
                    });
                }
                
                // For other requests, just fail
                return new Response('Network error', {
                    status: 408,
                    statusText: 'Network error'
                });
            })
    );
});

// Handle messages from the main thread
self.addEventListener('message', event => {
    console.log('Service Worker received message:', event.data);
    
    if (event.data && event.data.type === 'SKIP_WAITING') {
        self.skipWaiting();
    }
    
    if (event.data && event.data.type === 'CLEAR_CACHE') {
        caches.keys().then(cacheNames => {
            return Promise.all(
                cacheNames
                    .filter(name => name.startsWith('qms-'))
                    .map(name => caches.delete(name))
            );
        }).then(() => {
            console.log('All caches cleared');
            self.clients.matchAll().then(clients => {
                clients.forEach(client => {
                    client.postMessage({ type: 'CACHE_CLEARED' });
                });
            });
        });
    }
});

// Periodic cleanup of expired caches
self.addEventListener('periodicsync', event => {
    if (event.tag === 'cache-cleanup') {
        event.waitUntil(cleanupExpiredCache());
    }
});

async function cleanupExpiredCache() {
    try {
        const cache = await caches.open(API_CACHE);
        const requests = await cache.keys();
        const now = Date.now();
        
        for (const request of requests) {
            const response = await cache.match(request);
            if (response) {
                const timestamp = response.headers.get('sw-cache-timestamp');
                if (timestamp && (now - parseInt(timestamp)) > 30 * 60 * 1000) { // 30 minutes
                    await cache.delete(request);
                    console.log('Cleaned up expired cache entry:', request.url);
                }
            }
        }
    } catch (error) {
        console.error('Cache cleanup failed:', error);
    }
}