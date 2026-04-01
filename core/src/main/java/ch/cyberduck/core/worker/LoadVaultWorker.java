package ch.cyberduck.core.worker;

/*
 * Copyright (c) 2002-2019 iterate GmbH. All rights reserved.
 * https://cyberduck.io/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

import ch.cyberduck.core.LocaleFactory;
import ch.cyberduck.core.Path;
import ch.cyberduck.core.Session;
import ch.cyberduck.core.exception.BackgroundException;
import ch.cyberduck.core.features.Vault;
import ch.cyberduck.core.vault.VaultLoader;
import ch.cyberduck.core.vault.VaultVersion;

import java.util.Objects;

public class LoadVaultWorker extends Worker<Vault> {

    private final VaultLoader loader;
    private final Path directory;
    private final VaultVersion version;

    public LoadVaultWorker(final VaultLoader loader, final Path directory, final VaultVersion version) {
        this.loader = loader;
        this.directory = directory;
        this.version = version;
    }

    @Override
    public Vault run(final Session<?> session) throws BackgroundException {
        return loader.load(session, directory, version);
    }

    @Override
    public String getActivity() {
        return LocaleFactory.localizedString("Unlock Vault", "Cryptomator");
    }

    @Override
    public boolean equals(final Object o) {
        if(this == o) {
            return true;
        }
        if(o == null || getClass() != o.getClass()) {
            return false;
        }
        final LoadVaultWorker that = (LoadVaultWorker) o;
        return Objects.equals(version, that.version);
    }

    @Override
    public int hashCode() {
        return Objects.hash(version);
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("LoadVaultWorker{");
        sb.append("metadata=").append(version);
        sb.append('}');
        return sb.toString();
    }
}
