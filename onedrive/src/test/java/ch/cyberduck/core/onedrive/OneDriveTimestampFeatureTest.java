package ch.cyberduck.core.onedrive;

/*
 * Copyright (c) 2002-2018 iterate GmbH. All rights reserved.
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

import ch.cyberduck.core.AlphanumericRandomStringService;
import ch.cyberduck.core.DisabledListProgressListener;
import ch.cyberduck.core.DisabledLoginCallback;
import ch.cyberduck.core.Path;
import ch.cyberduck.core.PathAttributes;
import ch.cyberduck.core.SimplePathPredicate;
import ch.cyberduck.core.features.Delete;
import ch.cyberduck.core.features.Timestamp;
import ch.cyberduck.core.onedrive.features.GraphAttributesFinderFeature;
import ch.cyberduck.core.onedrive.features.GraphDeleteFeature;
import ch.cyberduck.core.onedrive.features.GraphDirectoryFeature;
import ch.cyberduck.core.onedrive.features.GraphTimestampFeature;
import ch.cyberduck.core.onedrive.features.GraphTouchFeature;
import ch.cyberduck.core.shared.DefaultAttributesFinderFeature;
import ch.cyberduck.core.transfer.TransferStatus;
import ch.cyberduck.test.IntegrationTest;

import org.junit.Test;
import org.junit.experimental.categories.Category;

import java.util.Collections;
import java.util.EnumSet;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

@Category(IntegrationTest.class)
public class OneDriveTimestampFeatureTest extends AbstractOneDriveTest {

    @Test
    public void testSetTimestamp() throws Exception {
        final Path drive = new OneDriveHomeFinderService().find();
        final Path file = new Path(drive, new AlphanumericRandomStringService().random(), EnumSet.of(Path.Type.file));
        new GraphTouchFeature(session, fileid).touch(file, new TransferStatus().setMime("x-application/cyberduck"));
        final PathAttributes attr = new GraphAttributesFinderFeature(session, fileid).find(file);
        assertNotEquals(PathAttributes.EMPTY, attr);
        final long modified = 1671187993791L;
        final TransferStatus status = new TransferStatus();
        new GraphTimestampFeature(session, fileid).setTimestamp(file, status.setModified(modified));
        final PathAttributes updated = new GraphAttributesFinderFeature(session, fileid).find(file);
        assertEquals(status.getResponse(), updated);
        assertEquals(Timestamp.toSeconds(modified), Timestamp.toSeconds(updated.getModificationDate()));
        assertNotEquals(attr.getETag(), updated.getETag());
        assertEquals(Timestamp.toSeconds(modified), new DefaultAttributesFinderFeature(session).find(file).getModificationDate());
        assertEquals(Timestamp.toSeconds(modified), Timestamp.toSeconds(new GraphItemListService(session, fileid).list(drive, new DisabledListProgressListener()).find(new SimplePathPredicate(file)).attributes().getModificationDate()));
        new GraphDeleteFeature(session, fileid).delete(Collections.singletonList(file), new DisabledLoginCallback(), new Delete.DisabledCallback());
    }

    @Test
    public void testSetTimestampDirectory() throws Exception {
        final Path drive = new OneDriveHomeFinderService().find();
        final Path test = new Path(drive, new AlphanumericRandomStringService().random(), EnumSet.of(Path.Type.directory));
        new GraphDirectoryFeature(session, fileid).mkdir(test, null);
        final PathAttributes attr = new GraphAttributesFinderFeature(session, fileid).find(test);
        assertNotEquals(PathAttributes.EMPTY, attr);
        final long modified = 1671187993791L;
        final TransferStatus status = new TransferStatus();
        new GraphTimestampFeature(session, fileid).setTimestamp(test, status.setModified(modified));
        final PathAttributes updated = new GraphAttributesFinderFeature(session, fileid).find(test);
        assertEquals(status.getResponse(), updated);
        assertEquals(Timestamp.toSeconds(modified), Timestamp.toSeconds(updated.getModificationDate()));
        assertNotEquals(attr.getETag(), updated.getETag());
        assertEquals(Timestamp.toSeconds(modified), Timestamp.toSeconds(new GraphItemListService(session, fileid).list(drive, new DisabledListProgressListener()).find(new SimplePathPredicate(test)).attributes().getModificationDate()));
        new GraphDeleteFeature(session, fileid).delete(Collections.singletonList(test), new DisabledLoginCallback(), new Delete.DisabledCallback());
    }
}
