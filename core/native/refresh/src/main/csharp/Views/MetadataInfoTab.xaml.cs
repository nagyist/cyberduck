using Ch.Cyberduck.Core.Refresh.ViewModels.Info;
using ReactiveMarbles.ObservableEvents;
using ReactiveUI;
using System.Threading.Tasks;

namespace Ch.Cyberduck.Core.Refresh.Views
{
    /// <summary>
    /// Interaktionslogik für MetadataInfoTab.xaml
    /// </summary>
    public partial class MetadataInfoTab
    {
        public MetadataInfoTab()
        {
            InitializeComponent();

            this.WhenActivated(d =>
            {
                d(this.BindInteraction(ViewModel, vm => vm.EditItem, c =>
                {
                    /* TODO */
                    return Task.CompletedTask;
                }));
                d(this.BindInteraction(ViewModel, vm => vm.Recurse, c =>
                {
                    /* TODO */
                    return Task.CompletedTask;
                }));

                var metadataGridEvents = HeadersGrid.Events();
                d(metadataGridEvents.AddingNewItem.InvokeCommand(this, v => v.ViewModel.AddingNewItem));
                d(metadataGridEvents.RowEditEnding.InvokeCommand(this, v => v.ViewModel.RowEditEnding));
            });
        }
    }

    public abstract class MetadataInfoTabBase : ReactiveUserControl<MetadataViewModel> { }
}
