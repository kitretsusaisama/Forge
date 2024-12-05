use anyhow::{Result, Context};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Represents a geographical region
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GeoRegion {
    Continent(String),
    Country(String),
    State(String),
    City(String),
}

/// Geolocation information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoLocation {
    pub ip_address: IpAddr,
    pub continent: Option<String>,
    pub country: Option<String>,
    pub state: Option<String>,
    pub city: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub timezone: Option<String>,
}

/// Access control policy based on geolocation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoAccessPolicy {
    pub allowed_regions: HashSet<GeoRegion>,
    pub blocked_regions: HashSet<GeoRegion>,
    pub max_distance_km: Option<f64>,
    pub reference_location: Option<(f64, f64)>,
}

/// Geolocation IP lookup service
#[derive(Debug, Clone)]
pub struct GeolocationService {
    // In-memory cache for geolocation results
    cache: Arc<RwLock<HashMap<IpAddr, GeoLocation>>>,
    
    // External IP geolocation providers
    providers: Vec<Box<dyn GeoLocationProvider>>,
}

/// Trait for geolocation providers
#[async_trait::async_trait]
pub trait GeoLocationProvider {
    /// Lookup geolocation for an IP address
    async fn lookup(&self, ip: IpAddr) -> Result<GeoLocation>;
    
    /// Provider name for logging and tracking
    fn name(&self) -> &'static str;
}

/// IP Geolocation Provider using MaxMind GeoIP database
pub struct MaxMindGeoLocationProvider {
    database: Arc<maxminddb::Reader<Vec<u8>>>,
}

impl MaxMindGeoLocationProvider {
    pub fn new(database_path: &str) -> Result<Self> {
        let database = Arc::new(maxminddb::Reader::open_readfile(database_path)?);
        Ok(Self { database })
    }
}

#[async_trait::async_trait]
impl GeoLocationProvider for MaxMindGeoLocationProvider {
    async fn lookup(&self, ip: IpAddr) -> Result<GeoLocation> {
        // Lookup geolocation in MaxMind database
        let city_data: maxminddb::geoip2::City = self.database.lookup(ip)?;
        
        Ok(GeoLocation {
            ip_address: ip,
            continent: city_data.continent.and_then(|c| c.names).and_then(|n| n.get("en").cloned()),
            country: city_data.country.and_then(|c| c.names).and_then(|n| n.get("en").cloned()),
            state: city_data.subdivisions.first()
                .and_then(|s| s.names.clone())
                .and_then(|n| n.get("en").cloned()),
            city: city_data.city.and_then(|c| c.names).and_then(|n| n.get("en").cloned()),
            latitude: city_data.location.map(|l| l.latitude).flatten(),
            longitude: city_data.location.map(|l| l.longitude).flatten(),
            timezone: city_data.location.and_then(|l| l.time_zone),
        })
    }
    
    fn name(&self) -> &'static str {
        "MaxMind GeoIP"
    }
}

/// Geolocation-based access control manager
pub struct GeolocationAccessControlManager {
    policies: HashMap<String, GeoAccessPolicy>,
    geolocation_service: GeolocationService,
}

impl GeolocationAccessControlManager {
    pub fn new(geolocation_service: GeolocationService) -> Self {
        Self {
            policies: HashMap::new(),
            geolocation_service,
        }
    }

    /// Add a new access policy for a specific resource or user
    pub fn add_policy(&mut self, resource_id: String, policy: GeoAccessPolicy) {
        self.policies.insert(resource_id, policy);
    }

    /// Check if access is allowed based on geolocation
    pub async fn is_access_allowed(
        &self, 
        resource_id: &str, 
        ip_address: IpAddr
    ) -> Result<bool> {
        // Retrieve policy for the resource
        let policy = self.policies.get(resource_id)
            .context("No geolocation policy found for resource")?;
        
        // Lookup geolocation for IP
        let location = self.geolocation_service.lookup_ip(ip_address).await?;
        
        // Check region-based access
        let region_allowed = self.check_region_access(policy, &location);
        
        // Check distance-based access if reference location is set
        let distance_allowed = self.check_distance_access(policy, &location);
        
        Ok(region_allowed && distance_allowed)
    }

    /// Check if the location matches allowed/blocked regions
    fn check_region_access(&self, policy: &GeoAccessPolicy, location: &GeoLocation) -> bool {
        // If no regions are specified, allow access
        if policy.allowed_regions.is_empty() && policy.blocked_regions.is_empty() {
            return true;
        }

        // Check blocked regions first
        if let Some(country) = &location.country {
            if policy.blocked_regions.contains(&GeoRegion::Country(country.clone())) {
                return false;
            }
        }

        // If allowed regions are specified, check against them
        if !policy.allowed_regions.is_empty() {
            let location_regions = [
                location.continent.clone().map(GeoRegion::Continent),
                location.country.clone().map(GeoRegion::Country),
                location.state.clone().map(GeoRegion::State),
                location.city.clone().map(GeoRegion::City),
            ];

            return location_regions.iter()
                .filter_map(|r| r.clone())
                .any(|region| policy.allowed_regions.contains(&region));
        }

        true
    }

    /// Check distance constraints
    fn check_distance_access(&self, policy: &GeoAccessPolicy, location: &GeoLocation) -> bool {
        // If no distance constraint or reference location is set, allow access
        let (ref_lat, ref_lon) = match policy.reference_location {
            Some(loc) => loc,
            None => return true,
        };

        let max_distance = match policy.max_distance_km {
            Some(dist) => dist,
            None => return true,
        };

        // Check if location coordinates are available
        let (lat, lon) = match (location.latitude, location.longitude) {
            (Some(lat), Some(lon)) => (lat, lon),
            _ => return true, // Cannot determine distance
        };

        // Calculate distance using Haversine formula
        let earth_radius_km = 6371.0;
        let dlat = (lat - ref_lat).to_radians();
        let dlon = (lon - ref_lon).to_radians();
        
        let a = (dlat/2.0).sin().powi(2) + 
                ref_lat.to_radians().cos() * lat.to_radians().cos() * 
                (dlon/2.0).sin().powi(2);
        let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());
        let distance = earth_radius_km * c;

        distance <= max_distance
    }
}

impl GeolocationService {
    pub fn new(providers: Vec<Box<dyn GeoLocationProvider>>) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            providers,
        }
    }

    /// Lookup IP geolocation with caching
    pub async fn lookup_ip(&self, ip: IpAddr) -> Result<GeoLocation> {
        // Check cache first
        {
            let cache_read = self.cache.read().await;
            if let Some(cached_location) = cache_read.get(&ip) {
                return Ok(cached_location.clone());
            }
        }

        // Lookup from providers
        for provider in &self.providers {
            match provider.lookup(ip).await {
                Ok(location) => {
                    // Cache the result
                    let mut cache_write = self.cache.write().await;
                    cache_write.insert(ip, location.clone());
                    return Ok(location);
                },
                Err(_) => continue,
            }
        }

        Err(anyhow::anyhow!("Unable to lookup geolocation for IP"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[tokio::test]
    async fn test_geolocation_access_control() {
        // Mock MaxMind provider (in real scenario, use actual database)
        struct MockGeoLocationProvider;
        
        #[async_trait::async_trait]
        impl GeoLocationProvider for MockGeoLocationProvider {
            async fn lookup(&self, ip: IpAddr) -> Result<GeoLocation> {
                Ok(GeoLocation {
                    ip_address: ip,
                    continent: Some("North America".to_string()),
                    country: Some("United States".to_string()),
                    state: Some("California".to_string()),
                    city: Some("San Francisco".to_string()),
                    latitude: Some(37.7749),
                    longitude: Some(-122.4194),
                    timezone: Some("America/Los_Angeles".to_string()),
                })
            }
            
            fn name(&self) -> &'static str {
                "Mock Provider"
            }
        }

        // Create geolocation service
        let geolocation_service = GeolocationService::new(vec![
            Box::new(MockGeoLocationProvider)
        ]);

        // Create access control manager
        let mut access_control = GeolocationAccessControlManager::new(geolocation_service);

        // Define policy
        let policy = GeoAccessPolicy {
            allowed_regions: vec![
                GeoRegion::Country("United States".to_string()),
                GeoRegion::State("California".to_string())
            ].into_iter().collect(),
            blocked_regions: HashSet::new(),
            max_distance_km: Some(100.0),
            reference_location: Some((37.7749, -122.4194)), // San Francisco coordinates
        };

        // Add policy
        access_control.add_policy("test_resource".to_string(), policy);

        // Test IP
        let test_ip = IpAddr::from_str("8.8.8.8").unwrap();

        // Check access
        let access_result = access_control.is_access_allowed("test_resource", test_ip).await;
        assert!(access_result.unwrap(), "Access should be allowed");
    }
}
