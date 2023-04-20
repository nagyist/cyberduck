using ch.cyberduck.core;
using ch.cyberduck.core.features;
using ch.cyberduck.core.pool;
using ch.cyberduck.core.threading;
using ch.cyberduck.core.worker;
using DynamicData.Binding;
using java.util;
using ReactiveUI;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Reactive;
using System.Reactive.Disposables;
using System.Reactive.Linq;
using System.Threading.Tasks;
using System.Windows.Controls;
using Collection = java.util.Collection;
using Observable = System.Reactive.Linq.Observable;

namespace Ch.Cyberduck.Core.Refresh.ViewModels.Info
{
    public class MetadataViewModel : ReactiveObject, Worker.RecursiveCallback
    {
        private readonly ObservableAsPropertyHelper<bool> busy;
        private readonly Controller controller;
        private readonly Headers headers;
        private readonly ObservableCollectionExtended<Entry> metadata = new();
        private readonly SessionPool session;
        private bool adding;
        private bool discard;

        public ReactiveCommand<AddingNewItemEventArgs, Unit> AddingNewItem { get; }

        public bool Busy => busy.Value;

        public Interaction<Unit, Unit> EditItem { get; } = new();

        public ReactiveCommand<Unit, Map> Load { get; }

        public Interaction<(Path Directory, object Value), bool> Recurse { get; } = new();

        public ReactiveCommand<DataGridRowEditEndingEventArgs, Unit> RowEditEnding { get; }

        public ReactiveCommand<Unit, Unit> Save { get; }

        public MetadataViewModel(Headers headers, Controller controller, SessionPool session)
        {
            (this.headers, this.controller, this.session) = (headers, controller, session);

            Load = ReactiveCommand.CreateFromTask(OnLoadAsync);
            Save = ReactiveCommand.CreateFromTask(OnSaveAsync);
            AddingNewItem = ReactiveCommand.Create<AddingNewItemEventArgs>(OnAddingNewItem);
            RowEditEnding = ReactiveCommand.Create<DataGridRowEditEndingEventArgs>(OnRowEditEnding);
            busy = Observable.Concat(Load.IsExecuting, Save.IsExecuting).ToProperty(this, nameof(Busy));

            var loadScan = Load.Scan((List: metadata, Subscriptions: new CompositeDisposable()), (acc, val) =>
            {
                var (List, Subscriptions) = acc;
                using (List.SuspendNotifications())
                {
                    Subscriptions.Dispose();
                    List.Load(val.entrySet().AsEnumerable<Map.Entry>().Select(s => new Entry(s)));
                }

                return (List, new());
            });
            var changeNotifications = Observable.Create<NotifyCollectionChangedEventArgs>(outer =>
            {
                SerialDisposable serialDisposable = new();
                return StableCompositeDisposable.Create(serialDisposable, loadScan.Subscribe(inner =>
                {
                    serialDisposable.DisposeWith(inner.Subscriptions);
                    serialDisposable.Disposable = inner.List.ObserveCollectionChanges().Select(s => s.EventArgs).Subscribe(outer);
                }));
            }).Subscribe(OnChanged);
        }

        private void OnAddingNewItem(AddingNewItemEventArgs args)
        {
            adding = true;
        }

        private void OnChanged(EventArgs obj)
        {
            (bool adding, bool discard, this.adding, this.discard) = (this.adding, this.discard, false, false);

            if (discard || adding)
            {
                return;
            }

            Observable.RunAsync(Save.Execute(), default).Subscribe();
        }

        private Task<Map> OnLoadAsync()
        {
            ReadMetadataWorkerImpl worker = new(/* TODO */ default);
            controller.background(new WorkerBackgroundAction(controller, session, worker));
            return worker.Result;
        }

        private void OnRowEditEnding(DataGridRowEditEndingEventArgs args)
        {
            discard = args.EditAction == DataGridEditAction.Cancel;
        }

        private Task OnSaveAsync()
        {
            return Task.Factory.StartNew(Run);

            void Run()
            {
                HashMap copy = new(metadata.Count);
                foreach (var item in metadata)
                {
                    copy.put(item.Key, item.Value);
                }

                var worker = new WriteMetadataWorker(/* TODO */ default, copy, this, new DisabledProgressListener());
            }
        }

        bool Worker.RecursiveCallback.recurse(Path directory, object value)
        {
            return Recurse.Handle((directory, value)).Wait();
        }

        private class ReadMetadataWorkerImpl : ReadMetadataWorker
        {
            private readonly TaskCompletionSource<Map> result = new();

            public Task<Map> Result => result.Task;

            public ReadMetadataWorkerImpl(List files) : base(files)
            {
            }

            public override void cleanup(object result) => this.result.SetResult((Map)result);
        }

        public record class Entry(string Key, string Value) : ReactiveRecord
        {
            private string key = Key;
            private string value = Value;

            public string Key
            {
                get => key;
                set => this.RaiseAndSetIfChanged(ref key, value);
            }

            public string Value
            {
                get => value;
                set => this.RaiseAndSetIfChanged(ref this.value, value);
            }

            public Entry(Map.Entry entry) : this((string)entry.getKey(), (string)entry.getValue())
            {
            }
        }
    }

    file static class Extensions
    {
        public static CollectionEnumerable<T> AsEnumerable<T>(this Collection collection) => new(collection);

        public class CollectionEnumerable<T> : IEnumerable<T>
        {
            private readonly Collection collection;

            public struct Enumerator : IEnumerator<T>
            {
                private readonly Collection collection;
                private T current;
                private Iterator iterator;

                public T Current => current;

                object IEnumerator.Current => current;

                public Enumerator(Collection collection)
                {
                    this.collection = collection;
                }

                public void Dispose()
                {
                }

                public bool MoveNext()
                {
                    if (iterator is null)
                    {
                        Reset();
                    }

                    bool next = iterator.hasNext();
                    if (next)
                    {
                        current = (T)iterator.next();
                    }

                    return next;
                }

                public void Reset()
                {
                    iterator = collection.iterator();
                }
            }

            public CollectionEnumerable(Collection collection)
            {
                this.collection = collection;
            }

            public Enumerator GetEnumerator() => new(collection);

            IEnumerator<T> IEnumerable<T>.GetEnumerator() => GetEnumerator();

            IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
        }
    }
}
