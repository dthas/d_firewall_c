package basicCompoment;  
      
import javax.swing.JFrame;  
import javax.swing.SwingUtilities;  
import javax.swing.WindowConstants;  
      
public class win_test extends JFrame
{  
        win_test()
	{  
            initGUI();  
        }
  
        private void initGUI()
	{  
            setVisible(true);  
            setSize(300,400);  
            setLocationRelativeTo(null);  
            setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);  
        }
  
        public static void main(String[] args) 
	{  
            	SwingUtilities.invokeLater(new Runnable() 
			{  
                		public void run() 
				{  
                    			win_test f = new win_test();  
                		}                 
            		});  
        }  
}  
