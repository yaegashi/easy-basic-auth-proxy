metadata description = 'Creates a container app in an Azure Container App environment.'
param name string
param location string = resourceGroup().location
param tags object = {}
param storageAccountName string
param containerAppsEnvironmentName string

resource storage 'Microsoft.Storage/storageAccounts@2022-05-01' existing = {
  name: storageAccountName
  resource fileService 'fileServices' = {
    name: 'default'
    resource data 'shares' = {
      name: 'data'
    }
  }
}

resource containerAppsEnvironment 'Microsoft.App/managedEnvironments@2023-04-01-preview' existing = {
  name: containerAppsEnvironmentName
  resource data 'storages' = {
    name: 'data'
    properties: {
      azureFile: {
        accessMode: 'ReadWrite'
        accountName: storage.name
        accountKey: storage.listKeys().keys[0].value
        shareName: storage::fileService::data.name
      }
    }
  }
}

resource app 'Microsoft.App/containerApps@2023-04-01-preview' = {
  name: name
  location: location
  tags: tags
  properties: {
    managedEnvironmentId: containerAppsEnvironment.id
    configuration: {
      ingress: {
        external: true
        targetPort: 80
      }
    }
    template: {
      volumes: [
        {
          name: 'data'
          storageName: storage::fileService::data.name
          storageType: 'AzureFile'
        }
      ]
      containers: [
        {
          name: 'ebap'
          image: 'ghcr.io/yaegashi/easy-basic-auth-proxy:main'
          env: [
            { name: 'EBAP_LISTEN', value: ':80' }
            { name: 'EBAP_TARGET_URL', value: 'http://localhost:8080' }
            { name: 'EBAP_ACCOUNTS_DIR', value: '/data/ebap/accounts' }
          ]
          volumeMounts: [
            {
              volumeName: 'data'
              subPath: 'ebap'
              mountPath: '/data/ebap'
            }
          ]
        }
        {
          name: 'whoami'
          image: 'traefik/whoami'
          args: [ '--port=8080' ]
        }
      ]
      scale: {
        minReplicas: 1
        maxReplicas: 1
      }
    }
  }
}
