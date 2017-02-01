    package basicCompoment;  
      
    import javax.swing.JFrame;  
    import javax.swing.WindowConstants;  
      
    public class win_test_1 extends JFrame{  
      
        public static void main(String[] args) {  
            //现在创建了一个对象，不过什么都显示不出来  
            win_test_1 f = new win_test_1();  
            //加上这一句就可以显示一个仅有关闭，最小化，最大化的按钮的Frame了  
            f.setVisible(true);  
            //再加上这一句就可以显示一个在左上角，拥有指定大小的Frame了  
            f.setSize(300,400);  
            //再加上这一句就可以把Frame放在最中间了  
            f.setLocationRelativeTo(null);  
            //如果没有这一句，在点击关闭Frame的时候程序其实还是在执行状态中的，加上这一句才算是真正的把资源释放掉了  
            f.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);  
        }  
    }  
