package ch.cyberduck.core.irods;

/*
 * Copyright (c) 2002-2015 David Kocher. All rights reserved.
 * http://cyberduck.ch/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * Bug fixes, suggestions and comments should be sent to feedback@cyberduck.ch
 */

import ch.cyberduck.core.Credentials;
import ch.cyberduck.core.DisabledCancelCallback;
import ch.cyberduck.core.DisabledConnectionCallback;
import ch.cyberduck.core.DisabledHostKeyCallback;
import ch.cyberduck.core.DisabledLoginCallback;
import ch.cyberduck.core.Host;
import ch.cyberduck.core.Path;
import ch.cyberduck.core.PathAttributes;
import ch.cyberduck.core.Profile;
import ch.cyberduck.core.ProtocolFactory;
import ch.cyberduck.core.exception.BackgroundException;
import ch.cyberduck.core.features.Delete;
import ch.cyberduck.core.features.Find;
import ch.cyberduck.core.features.Read;
import ch.cyberduck.core.io.StatusOutputStream;
import ch.cyberduck.core.io.StreamCopier;
import ch.cyberduck.core.proxy.DisabledProxyFinder;
import ch.cyberduck.core.serializer.impl.dd.ProfilePlistReader;
import ch.cyberduck.core.transfer.TransferStatus;
import ch.cyberduck.test.IntegrationTest;
import ch.cyberduck.test.VaultTest;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.RandomUtils;
import org.irods.jargon.core.pub.domain.ObjStat;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;

import static org.junit.Assert.*;

@Category(IntegrationTest.class)
public class IRODSWriteFeatureTest extends VaultTest {

    @Test
    public void testWriteConcurrent() throws Exception {
        final ProtocolFactory factory = new ProtocolFactory(new HashSet<>(Collections.singleton(new IRODSProtocol())));
        final Profile profile = new ProfilePlistReader(factory).read(
                this.getClass().getResourceAsStream("/iRODS (iPlant Collaborative).cyberduckprofile"));
        final Host host = new Host(profile, profile.getDefaultHostname(), new Credentials(
                PROPERTIES.get("irods.key"), PROPERTIES.get("irods.secret")
        ));

        final IRODSSession session1 = new IRODSSession(host);
        session1.open(new DisabledProxyFinder(), new DisabledHostKeyCallback(), new DisabledLoginCallback(), new DisabledCancelCallback());
        session1.login(new DisabledLoginCallback(), new DisabledCancelCallback());

        final IRODSSession session2 = new IRODSSession(host);
        session2.open(new DisabledProxyFinder(), new DisabledHostKeyCallback(), new DisabledLoginCallback(), new DisabledCancelCallback());
        session2.login(new DisabledLoginCallback(), new DisabledCancelCallback());

        final Path test1 = new Path(new IRODSHomeFinderService(session1).find(), UUID.randomUUID().toString(), EnumSet.of(Path.Type.file));
        final Path test2 = new Path(new IRODSHomeFinderService(session2).find(), UUID.randomUUID().toString(), EnumSet.of(Path.Type.file));

        final byte[] content = RandomUtils.nextBytes(68400);

        final OutputStream out1 = new IRODSWriteFeature(session1).write(test1, new TransferStatus().setAppend(false).setLength(content.length), new DisabledConnectionCallback());
        final OutputStream out2 = new IRODSWriteFeature(session2).write(test2, new TransferStatus().setAppend(false).setLength(content.length), new DisabledConnectionCallback());
        new StreamCopier(new TransferStatus(), new TransferStatus()).transfer(new ByteArrayInputStream(content), out2);
        // Error code received from iRODS:-23000
        new StreamCopier(new TransferStatus(), new TransferStatus()).transfer(new ByteArrayInputStream(content), out1);

        {
            final InputStream in1 = session1.getFeature(Read.class).read(test1, new TransferStatus(), new DisabledConnectionCallback());
            final byte[] buffer1 = new byte[content.length];
            IOUtils.readFully(in1, buffer1);
            in1.close();
            assertArrayEquals(content, buffer1);
        }
        {
            final InputStream in2 = session2.getFeature(Read.class).read(test2, new TransferStatus(), new DisabledConnectionCallback());
            final byte[] buffer2 = new byte[content.length];
            IOUtils.readFully(in2, buffer2);
            in2.close();
            assertArrayEquals(content, buffer2);
        }
        session1.close();
        session2.close();
    }

    @Test
    public void testWriteThreaded() throws Exception {
        final ProtocolFactory factory = new ProtocolFactory(new HashSet<>(Collections.singleton(new IRODSProtocol())));
        final Profile profile = new ProfilePlistReader(factory).read(
                this.getClass().getResourceAsStream("/iRODS (iPlant Collaborative).cyberduckprofile"));
        final Host host = new Host(profile, profile.getDefaultHostname(), new Credentials(
                PROPERTIES.get("irods.key"), PROPERTIES.get("irods.secret")
        ));

        final IRODSSession session1 = new IRODSSession(host);
        session1.open(new DisabledProxyFinder(), new DisabledHostKeyCallback(), new DisabledLoginCallback(), new DisabledCancelCallback());
        session1.login(new DisabledLoginCallback(), new DisabledCancelCallback());

        final IRODSSession session2 = new IRODSSession(host);
        session2.open(new DisabledProxyFinder(), new DisabledHostKeyCallback(), new DisabledLoginCallback(), new DisabledCancelCallback());
        session2.login(new DisabledLoginCallback(), new DisabledCancelCallback());

        final CountDownLatch cw1 = new CountDownLatch(1);
        final CountDownLatch cw2 = new CountDownLatch(1);

        final Path test1 = new Path(new IRODSHomeFinderService(session1).find(), UUID.randomUUID().toString(), EnumSet.of(Path.Type.file));
        final Path test2 = new Path(new IRODSHomeFinderService(session2).find(), UUID.randomUUID().toString(), EnumSet.of(Path.Type.file));

        final byte[] content = RandomUtils.nextBytes(68400);

        final OutputStream out1 = new IRODSWriteFeature(session1).write(test1, new TransferStatus().setAppend(false).setLength(content.length), new DisabledConnectionCallback());
        final OutputStream out2 = new IRODSWriteFeature(session2).write(test2, new TransferStatus().setAppend(false).setLength(content.length), new DisabledConnectionCallback());
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    new StreamCopier(new TransferStatus(), new TransferStatus()).transfer(new ByteArrayInputStream(content), out2);
                }
                catch(BackgroundException e) {
                    fail();
                }
                finally {
                    cw1.countDown();
                }
            }
        }).start();
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    new StreamCopier(new TransferStatus(), new TransferStatus()).transfer(new ByteArrayInputStream(content), out1);
                }
                catch(BackgroundException e) {
                    fail();
                }
                finally {
                    cw2.countDown();
                }
            }
        }).start();

        cw1.await();
        cw2.await();

        final CountDownLatch cr1 = new CountDownLatch(1);
        final CountDownLatch cr2 = new CountDownLatch(1);

        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    final InputStream in1 = session1.getFeature(Read.class).read(test1, new TransferStatus(), new DisabledConnectionCallback());
                    final byte[] buffer1 = new byte[content.length];
                    IOUtils.readFully(in1, buffer1);
                    in1.close();
                    assertArrayEquals(content, buffer1);
                }
                catch(Exception e) {
                    fail();
                }
                finally {
                    cr1.countDown();
                }
            }
        }).start();
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    final InputStream in2 = session2.getFeature(Read.class).read(test2, new TransferStatus(), new DisabledConnectionCallback());
                    final byte[] buffer2 = new byte[content.length];
                    IOUtils.readFully(in2, buffer2);
                    in2.close();
                    assertArrayEquals(content, buffer2);
                }
                catch(Exception e) {
                    fail();
                }
                finally {
                    cr2.countDown();
                }
            }
        }).start();

        cr1.await();
        cr2.await();

        session1.close();
        session2.close();
    }

    @Test
    public void testWrite() throws Exception {
        final ProtocolFactory factory = new ProtocolFactory(new HashSet<>(Collections.singleton(new IRODSProtocol())));
        final Profile profile = new ProfilePlistReader(factory).read(
                this.getClass().getResourceAsStream("/iRODS (iPlant Collaborative).cyberduckprofile"));
        final Host host = new Host(profile, profile.getDefaultHostname(), new Credentials(
                PROPERTIES.get("irods.key"), PROPERTIES.get("irods.secret")
        ));

        final IRODSSession session = new IRODSSession(host);
        session.open(new DisabledProxyFinder(), new DisabledHostKeyCallback(), new DisabledLoginCallback(), new DisabledCancelCallback());
        session.login(new DisabledLoginCallback(), new DisabledCancelCallback());

        final Path test = new Path(new IRODSHomeFinderService(session).find(), UUID.randomUUID().toString(), EnumSet.of(Path.Type.file));
        assertFalse(session.getFeature(Find.class).find(test));

        final byte[] content = RandomUtils.nextBytes(100);
        final IRODSWriteFeature feature = new IRODSWriteFeature(session);
        {
            final TransferStatus status = new TransferStatus();
            status.setAppend(false);
            status.setLength(content.length);

            assertEquals(0L, new IRODSUploadFeature(session).append(test, status).offset, 0L);

            final StatusOutputStream<ObjStat> out = feature.write(test, status, new DisabledConnectionCallback());
            assertNotNull(out);

            new StreamCopier(new TransferStatus(), new TransferStatus()).transfer(new ByteArrayInputStream(content), out);
            assertTrue(session.getFeature(Find.class).find(test));

            final PathAttributes attributes = new IRODSAttributesFinderFeature(session).find(test);
            assertEquals(content.length, attributes.getSize());

            final InputStream in = session.getFeature(Read.class).read(test, new TransferStatus(), new DisabledConnectionCallback());
            final byte[] buffer = new byte[content.length];
            IOUtils.readFully(in, buffer);
            in.close();
            assertArrayEquals(content, buffer);
        }
        {
            final byte[] newcontent = RandomUtils.nextBytes(10);

            final TransferStatus status = new TransferStatus();
            status.setAppend(false);
            status.setLength(newcontent.length);
            status.setRemote(new IRODSAttributesFinderFeature(session).find(test));

            assertTrue(new IRODSUploadFeature(session).append(test, status).append);
            assertEquals(content.length, new IRODSUploadFeature(session).append(test, status).offset, 0L);

            final StatusOutputStream<ObjStat> out = feature.write(test, status, new DisabledConnectionCallback());
            assertNotNull(out);

            new StreamCopier(new TransferStatus(), new TransferStatus()).transfer(new ByteArrayInputStream(newcontent), out);
            assertTrue(session.getFeature(Find.class).find(test));

            final PathAttributes attributes = new IRODSAttributesFinderFeature(session).find(test);
            assertEquals(newcontent.length, attributes.getSize());
            assertEquals(new IRODSAttributesFinderFeature(session).toAttributes(out.getStatus()), attributes);

            final InputStream in = session.getFeature(Read.class).read(test, new TransferStatus(), new DisabledConnectionCallback());
            final byte[] buffer = new byte[newcontent.length];
            IOUtils.readFully(in, buffer);
            in.close();
            assertArrayEquals(newcontent, buffer);
        }

        session.getFeature(Delete.class).delete(Collections.singletonList(test), new DisabledLoginCallback(), new Delete.DisabledCallback());
        assertFalse(session.getFeature(Find.class).find(test));
        session.close();
    }

    @Test
    public void testWriteAppend() throws Exception {
        final ProtocolFactory factory = new ProtocolFactory(new HashSet<>(Collections.singleton(new IRODSProtocol())));
        final Profile profile = new ProfilePlistReader(factory).read(
                this.getClass().getResourceAsStream("/iRODS (iPlant Collaborative).cyberduckprofile"));
        final Host host = new Host(profile, profile.getDefaultHostname(), new Credentials(
                PROPERTIES.get("irods.key"), PROPERTIES.get("irods.secret")
        ));

        final IRODSSession session = new IRODSSession(host);
        session.open(new DisabledProxyFinder(), new DisabledHostKeyCallback(), new DisabledLoginCallback(), new DisabledCancelCallback());
        session.login(new DisabledLoginCallback(), new DisabledCancelCallback());

        final Path test = new Path(new IRODSHomeFinderService(session).find(), UUID.randomUUID().toString(), EnumSet.of(Path.Type.file));
        assertFalse(session.getFeature(Find.class).find(test));

        final byte[] content = RandomUtils.nextBytes(100);

        final TransferStatus status = new TransferStatus();
        status.setAppend(true);
        status.setLength(content.length);

        final IRODSWriteFeature feature = new IRODSWriteFeature(session);
        assertEquals(0L, new IRODSUploadFeature(session).append(test, status).offset, 0L);

        final OutputStream out = feature.write(test, status, new DisabledConnectionCallback());
        assertNotNull(out);

        new StreamCopier(new TransferStatus(), new TransferStatus()).transfer(new ByteArrayInputStream(content), out);
        assertTrue(session.getFeature(Find.class).find(test));

        final PathAttributes attributes = new IRODSAttributesFinderFeature(session).find(test);
        assertEquals(content.length, attributes.getSize());

        final InputStream in = session.getFeature(Read.class).read(test, new TransferStatus(), new DisabledConnectionCallback());
        final byte[] buffer = new byte[content.length];
        IOUtils.readFully(in, buffer);
        in.close();
        assertArrayEquals(content, buffer);

        // Append

        final byte[] content_append = RandomUtils.nextBytes(100);

        final TransferStatus status_append = new TransferStatus();
        status_append.setAppend(true);
        status_append.setLength(content_append.length);
        status_append.setRemote(new IRODSAttributesFinderFeature(session).find(test));

        assertTrue(new IRODSUploadFeature(session).append(test, status_append).append);
        assertEquals(status.getLength(), new IRODSUploadFeature(session).append(test, status_append).offset, 0L);

        final OutputStream out_append = feature.write(test, status_append, new DisabledConnectionCallback());
        assertNotNull(out_append);

        new StreamCopier(new TransferStatus(), new TransferStatus()).transfer(new ByteArrayInputStream(content_append), out_append);
        assertTrue(session.getFeature(Find.class).find(test));

        final PathAttributes attributes_complete = new IRODSAttributesFinderFeature(session).find(test);
        assertEquals(content.length + content_append.length, attributes_complete.getSize());

        final InputStream in_append = session.getFeature(Read.class).read(test, new TransferStatus(), new DisabledConnectionCallback());
        final byte[] buffer_complete = new byte[content.length + content_append.length];
        IOUtils.readFully(in_append, buffer_complete);
        in_append.close();

        byte[] complete = new byte[content.length + content_append.length];
        System.arraycopy(content, 0, complete, 0, content.length);
        System.arraycopy(content_append, 0, complete, content.length, content_append.length);
        assertArrayEquals(complete, buffer_complete);

        session.getFeature(Delete.class).delete(Collections.singletonList(test), new DisabledLoginCallback(), new Delete.DisabledCallback());
        assertFalse(session.getFeature(Find.class).find(test));
        session.close();
    }
}
