use std::path::PathBuf;
use async_trait::async_trait;
use anyhow::Result;
use aws_sdk_s3::{Client, Region};
use aws_config::meta::region::RegionProviderChain;
use aws_config::BehaviorVersion;
use crate::security::cloud_providers::{CloudProvider, CloudProviderConfig};
use crate::core::error::ForgeError;

pub struct AWSProvider {
    client: Client,
    bucket: String,
}

impl AWSProvider {
    pub async fn new(config: &CloudProviderConfig, bucket: String) -> Result<Self, ForgeError> {
        let region_provider = RegionProviderChain::first_try(Region::new(config.region.clone()));
        
        let aws_config = aws_config::defaults(BehaviorVersion::latest())
            .region(region_provider)
            .load()
            .await;

        let client = Client::new(&aws_config);

        Ok(Self {
            client,
            bucket,
        })
    }
}

#[async_trait]
impl CloudProvider for AWSProvider {
    async fn upload_file(&self, local_path: PathBuf, remote_path: &str) -> Result<String, ForgeError> {
        let body = aws_sdk_s3::types::ByteStream::from_path(&local_path)
            .await
            .map_err(|e| ForgeError::CloudProviderError(format!("Failed to read file: {}", e)))?;
        
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(remote_path)
            .body(body)
            .send()
            .await
            .map_err(|e| ForgeError::CloudProviderError(format!("Failed to upload file: {}", e)))?;

        Ok(format!("s3://{}/{}", self.bucket, remote_path))
    }

    async fn download_file(&self, remote_path: &str, local_path: PathBuf) -> Result<(), ForgeError> {
        let resp = self.client
            .get_object()
            .bucket(&self.bucket)
            .key(remote_path)
            .send()
            .await
            .map_err(|e| ForgeError::CloudProviderError(format!("Failed to download file: {}", e)))?;

        let data = resp.body
            .collect()
            .await
            .map_err(|e| ForgeError::CloudProviderError(format!("Failed to collect response: {}", e)))?;
            
        tokio::fs::write(local_path, data.into_bytes())
            .await
            .map_err(|e| ForgeError::CloudProviderError(format!("Failed to write file: {}", e)))?;
            
        Ok(())
    }

    async fn list_files(&self, prefix: &str) -> Result<Vec<String>, ForgeError> {
        let resp = self.client
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(prefix)
            .send()
            .await
            .map_err(|e| ForgeError::CloudProviderError(format!("Failed to list files: {}", e)))?;

        let mut files = Vec::new();
        if let Some(contents) = resp.contents {
            for object in contents {
                if let Some(key) = object.key {
                    files.push(key);
                }
            }
        }
        Ok(files)
    }

    async fn delete_file(&self, remote_path: &str) -> Result<(), ForgeError> {
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(remote_path)
            .send()
            .await
            .map_err(|e| ForgeError::CloudProviderError(format!("Failed to delete file: {}", e)))?;
        Ok(())
    }

    async fn get_signed_url(&self, remote_path: &str, expiry_seconds: u64) -> Result<String, ForgeError> {
        let presigned_req = self.client
            .get_object()
            .bucket(&self.bucket)
            .key(remote_path)
            .presigned(aws_sdk_s3::presigning::PresigningConfig::expires_in(
                std::time::Duration::from_secs(expiry_seconds),
            ).map_err(|e| ForgeError::CloudProviderError(format!("Failed to create presigning config: {}", e)))?)
            .await
            .map_err(|e| ForgeError::CloudProviderError(format!("Failed to generate signed URL: {}", e)))?;

        Ok(presigned_req.uri().to_string())
    }
}
