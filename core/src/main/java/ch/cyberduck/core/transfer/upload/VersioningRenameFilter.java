package ch.cyberduck.core.transfer.upload;

/*
 * Copyright (c) 2002-2023 iterate GmbH. All rights reserved.
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

import ch.cyberduck.core.DisabledConnectionCallback;
import ch.cyberduck.core.Local;
import ch.cyberduck.core.Path;
import ch.cyberduck.core.ProgressListener;
import ch.cyberduck.core.Session;
import ch.cyberduck.core.exception.BackgroundException;
import ch.cyberduck.core.features.Copy;
import ch.cyberduck.core.features.Delete;
import ch.cyberduck.core.features.Directory;
import ch.cyberduck.core.features.Move;
import ch.cyberduck.core.features.Versioning;
import ch.cyberduck.core.filter.UploadRegexFilter;
import ch.cyberduck.core.preferences.HostPreferences;
import ch.cyberduck.core.transfer.TransferStatus;
import ch.cyberduck.core.transfer.symlink.SymlinkResolver;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.List;
import java.util.regex.Pattern;

public class VersioningRenameFilter extends AbstractUploadFilter {
    private static final Logger log = LogManager.getLogger(VersioningRenameFilter.class);

    private final Session<?> session;
    private final Versioning versioning;

    public VersioningRenameFilter(final SymlinkResolver<Local> symlinkResolver, final Session<?> session, final UploadFilterOptions options) {
        super(symlinkResolver, session, options);
        this.session = session;
        this.versioning = session.getFeature(Versioning.class);
    }

    @Override
    public void apply(final Path file, final Local local, final TransferStatus status, final ProgressListener listener) throws BackgroundException {
        if(status.isExists()) {
            final String regex = new HostPreferences(session.getHost()).getProperty("queue.upload.file.versioning.include.regex");
            if(new UploadRegexFilter(Pattern.compile(regex)).accept(local)) {
                final Path version = versioning.toVersioned(file);
                if(session.getFeature(Move.class).isSupported(file, version)) {
                    final Path directory = version.getParent();
                    if(!find.find(directory)) {
                        if(log.isDebugEnabled()) {
                            log.debug(String.format("Create directory %s for versions", directory));
                        }
                        session.getFeature(Directory.class).mkdir(directory, new TransferStatus());
                    }
                    if(log.isDebugEnabled()) {
                        log.debug(String.format("Rename existing file %s to %s", file, version));
                    }
                    session.getFeature(Move.class).move(file, version,
                            new TransferStatus().exists(false), new Delete.DisabledCallback(), new DisabledConnectionCallback());
                    if(log.isDebugEnabled()) {
                        log.debug(String.format("Clear exist flag for file %s", file));
                    }
                    status.exists(false).getDisplayname().exists(false);
                }
            }
            else {
                if(log.isDebugEnabled()) {
                    log.debug(String.format("No match for %s in %s", file.getName(), regex));
                }
            }
        }
    }
}