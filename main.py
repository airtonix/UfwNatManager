
import pygtk; pygtk.require('2.0')
import gtk

def main():
    win = gtk.Window()
    win.props.title = 'UfwNatManager'
    
    win.connect('delete-event', lambda *_: gtk.main_quit())
	
    win.show()
    gtk.main()

if __name__ == '__main__':
    main()
