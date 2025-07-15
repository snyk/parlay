/*
 * © 2023 Snyk Limited All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package ecosystems

import (
	"sync"

	"github.com/package-url/packageurl-go"

	"github.com/snyk/parlay/ecosystems/packages"
)

type Cache interface {
	GetPackageData(purl packageurl.PackageURL) (*packages.GetRegistryPackageResponse, error)
	GetPackageVersionData(purl packageurl.PackageURL) (*packages.GetRegistryPackageVersionResponse, error)
}

type InMemoryCache struct {
	packageCache        map[string]*packages.GetRegistryPackageResponse
	packageVersionCache map[string]*packages.GetRegistryPackageVersionResponse
	mu                  sync.RWMutex
}

func NewInMemoryCache() *InMemoryCache {
	return &InMemoryCache{
		packageCache:        make(map[string]*packages.GetRegistryPackageResponse),
		packageVersionCache: make(map[string]*packages.GetRegistryPackageVersionResponse),
	}
}

func (c *InMemoryCache) GetPackageData(purl packageurl.PackageURL) (*packages.GetRegistryPackageResponse, error) {
	key := purl.ToString()

	c.mu.RLock()
	if cached, exists := c.packageCache[key]; exists {
		c.mu.RUnlock()
		return cached, nil
	}
	c.mu.RUnlock()

	response, err := GetPackageData(purl)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.packageCache[key] = response
	c.mu.Unlock()

	return response, nil
}

func (c *InMemoryCache) GetPackageVersionData(purl packageurl.PackageURL) (*packages.GetRegistryPackageVersionResponse, error) {
	key := purl.ToString()

	c.mu.RLock()
	if cached, exists := c.packageVersionCache[key]; exists {
		c.mu.RUnlock()
		return cached, nil
	}
	c.mu.RUnlock()

	response, err := GetPackageVersionData(purl)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.packageVersionCache[key] = response
	c.mu.Unlock()

	return response, nil
}

func (c *InMemoryCache) GetCacheStats() (int, int) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.packageCache), len(c.packageVersionCache)
}
